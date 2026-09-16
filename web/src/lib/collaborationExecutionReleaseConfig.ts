import type { RoyaltyReleaseConfiguration } from "./royaltyReleaseAuthority";

export const COLLABORATION_EXECUTION_RELEASE_SERVICE =
  "collaboration-execution-worker" as const;
export const COLLABORATION_EXECUTION_RELEASE_PROFILE =
  "collaboration-execution" as const;

type Sha256Pin = `sha256:${string}`;
type PublicEnv = Readonly<Record<string, string | boolean | undefined>>;

export interface CollaborationExecutionReleaseConfig {
  readonly configured: boolean;
  readonly issues: readonly string[];
  readonly releaseSha?: string;
  readonly finalReleaseAuthoritySha256?: Sha256Pin;
  readonly releaseVerificationSha256?: Sha256Pin;
  readonly service?: typeof COLLABORATION_EXECUTION_RELEASE_SERVICE;
  readonly profile?: typeof COLLABORATION_EXECUTION_RELEASE_PROFILE;
  readonly mainRuntimeCvmId?: string;
  readonly royaltyReleaseActiveStateSha256?: Sha256Pin;
  readonly royaltyReleaseHistorySha256?: Sha256Pin;
  readonly royaltyReleaseHistoryReceiptSha256?: Sha256Pin;
  /** Signed current-v4 control-plane release decision; not worker liveness. */
  readonly executionEnabled: boolean;
  /** Signed credential-adoption decision; false does not invalidate wallet-origin execution. */
  readonly walletAdoptionEnabled: boolean;
  /** Release configuration is not a liveness observation. */
  readonly workerPresenceProven: false;
  /** The browser projection makes no TDX claim. */
  readonly tdxAttestationClaimed: false;
  /** The browser projection makes no QVL-verification claim. */
  readonly qvlVerified: false;
  readonly truthStatus: "release-configured";
}

function clean(value: string | boolean | undefined): string {
  if (typeof value !== "string") return "";
  const normalized = value.trim();
  return normalized === "undefined" || normalized === "null" ? "" : normalized;
}

function sha256Pin(value: string): Sha256Pin | undefined {
  const normalized = value.toLowerCase();
  return /^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(normalized)
    ? normalized as Sha256Pin
    : undefined;
}

function releaseSha(value: string): string | undefined {
  const normalized = value.toLowerCase();
  return /^(?!0{40}$)[0-9a-f]{40}$/.test(normalized)
    ? normalized
    : undefined;
}

function cvmId(value: string): string | undefined {
  return /^[a-z0-9][a-z0-9._:-]{7,127}$/.test(value) ? value : undefined;
}

export function parseCollaborationExecutionReleaseConfig(
  env: PublicEnv,
  expected: Readonly<{
    releaseSha?: string;
    mainRuntimeCvmId?: string;
    collaborationEnabled: boolean;
    royaltyRelease: RoyaltyReleaseConfiguration;
  }>,
): CollaborationExecutionReleaseConfig {
  const raw = {
    finalReleaseAuthoritySha256: clean(env.VITE_FINAL_RELEASE_AUTHORITY_SHA256),
    releaseVerificationSha256: clean(
      env.VITE_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256,
    ),
    service: clean(env.VITE_COLLABORATION_EXECUTION_SERVICE),
    profile: clean(env.VITE_COLLABORATION_EXECUTION_PROFILE),
    releaseSha: clean(env.VITE_COLLABORATION_EXECUTION_RELEASE_SHA),
    mainRuntimeCvmId: clean(env.VITE_COLLABORATION_EXECUTION_MAIN_RUNTIME_CVM_ID),
    enabled: clean(env.VITE_COLLABORATION_EXECUTION_ENABLED),
    royaltyReleaseActiveStateSha256: clean(
      env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_SHA256,
    ),
    royaltyReleaseHistorySha256: clean(env.VITE_ROYALTY_RELEASE_HISTORY_SHA256),
    royaltyReleaseHistoryReceiptSha256: clean(
      env.VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256,
    ),
    walletAdoptionEnabled: clean(
      env.VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED,
    ),
  };
  const present = Object.values(raw).filter(Boolean).length;
  const issues: string[] = [];
  if (present === 0) {
    issues.push("Current v4 Collaboration execution release projection is not configured");
  } else if (present !== Object.keys(raw).length) {
    issues.push("Current v4 Collaboration execution release projection is incomplete");
  }

  const finalReleaseAuthoritySha256 = sha256Pin(raw.finalReleaseAuthoritySha256);
  const releaseVerificationSha256 = sha256Pin(raw.releaseVerificationSha256);
  const parsedReleaseSha = releaseSha(raw.releaseSha);
  const mainRuntimeCvmId = cvmId(raw.mainRuntimeCvmId);
  const royaltyReleaseActiveStateSha256 = sha256Pin(
    raw.royaltyReleaseActiveStateSha256,
  );
  const royaltyReleaseHistorySha256 = sha256Pin(
    raw.royaltyReleaseHistorySha256,
  );
  const royaltyReleaseHistoryReceiptSha256 = sha256Pin(
    raw.royaltyReleaseHistoryReceiptSha256,
  );

  if (present > 0 && (!finalReleaseAuthoritySha256
    || !releaseVerificationSha256
    || !parsedReleaseSha
    || !mainRuntimeCvmId
    || !royaltyReleaseActiveStateSha256
    || !royaltyReleaseHistorySha256
    || !royaltyReleaseHistoryReceiptSha256)) {
    issues.push("Collaboration execution release digests, release SHA, or main-runtime CVM ID are invalid");
  }
  if (present > 0 && (raw.service !== COLLABORATION_EXECUTION_RELEASE_SERVICE
    || raw.profile !== COLLABORATION_EXECUTION_RELEASE_PROFILE)) {
    issues.push("Collaboration execution service/profile is not the canonical current release");
  }
  if (present > 0 && raw.enabled !== "true" && raw.enabled !== "false") {
    issues.push("Collaboration execution decision is not a canonical boolean");
  }
  if (present > 0
    && raw.walletAdoptionEnabled !== "true"
    && raw.walletAdoptionEnabled !== "false") {
    issues.push("Compute-workload wallet-adoption decision is not a canonical boolean");
  }
  if (present > 0
    && raw.enabled === "true"
    && !expected.collaborationEnabled) {
    issues.push("Collaboration execution requires the broader Collaboration feature dependency");
  }
  if (!expected.releaseSha || !parsedReleaseSha
    || parsedReleaseSha !== expected.releaseSha.toLowerCase()) {
    issues.push("Collaboration execution release SHA drifts from the frontend release");
  }
  if (!expected.mainRuntimeCvmId || !mainRuntimeCvmId
    || mainRuntimeCvmId !== expected.mainRuntimeCvmId) {
    issues.push("Collaboration execution main-runtime CVM drifts from the frontend release");
  }
  if (!expected.royaltyRelease.configured
    || !expected.royaltyRelease.authority
    || !expected.royaltyRelease.activeState) {
    issues.push("Canonical Royalty authority and active-state JSON are not configured");
  }
  if (royaltyReleaseHistorySha256
    && royaltyReleaseHistorySha256 !== expected.royaltyRelease.historySha256) {
    issues.push("Collaboration execution Royalty history digest drifts from H");
  }
  if (royaltyReleaseHistoryReceiptSha256
    && royaltyReleaseHistoryReceiptSha256
      !== expected.royaltyRelease.historyReceiptSha256) {
    issues.push("Collaboration execution Royalty H receipt digest drifts from H");
  }
  const distinctDigests = [
    finalReleaseAuthoritySha256,
    releaseVerificationSha256,
    royaltyReleaseActiveStateSha256,
    royaltyReleaseHistorySha256,
    royaltyReleaseHistoryReceiptSha256,
  ].filter((value): value is Sha256Pin => Boolean(value));
  if (distinctDigests.length > 0
    && new Set(distinctDigests).size !== distinctDigests.length) {
    issues.push("Collaboration execution authority and Royalty evidence digests must remain distinct");
  }

  return Object.freeze({
    configured: issues.length === 0,
    issues: Object.freeze(issues),
    releaseSha: parsedReleaseSha,
    finalReleaseAuthoritySha256,
    releaseVerificationSha256,
    service: raw.service === COLLABORATION_EXECUTION_RELEASE_SERVICE
      ? COLLABORATION_EXECUTION_RELEASE_SERVICE
      : undefined,
    profile: raw.profile === COLLABORATION_EXECUTION_RELEASE_PROFILE
      ? COLLABORATION_EXECUTION_RELEASE_PROFILE
      : undefined,
    mainRuntimeCvmId,
    royaltyReleaseActiveStateSha256,
    royaltyReleaseHistorySha256,
    royaltyReleaseHistoryReceiptSha256,
    executionEnabled: raw.enabled === "true",
    walletAdoptionEnabled: raw.walletAdoptionEnabled === "true",
    workerPresenceProven: false,
    tdxAttestationClaimed: false,
    qvlVerified: false,
    truthStatus: "release-configured",
  });
}
