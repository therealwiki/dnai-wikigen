export type FrontendReleaseIdentity = Readonly<
  | {
    status: "release_bound";
    display: string;
    releaseSha: string;
    verificationChainReleaseSha: string;
  }
  | {
    status: "unconfigured_modeled";
    display: "unconfigured · modeled";
    releaseSha: undefined;
    verificationChainReleaseSha: undefined;
  }
>;

/**
 * A Git release identity exists only when the build supplies one exact SHA.
 * Friendly fallbacks such as "working-tree" are UI state, never provenance.
 */
export function parseFrontendReleaseIdentity(
  value: string | undefined,
): FrontendReleaseIdentity {
  const candidate = value?.trim().toLowerCase() ?? "";
  if (/^[0-9a-f]{40}$/.test(candidate)) {
    return Object.freeze({
      status: "release_bound" as const,
      display: candidate,
      releaseSha: candidate,
      verificationChainReleaseSha: candidate,
    });
  }
  return Object.freeze({
    status: "unconfigured_modeled" as const,
    display: "unconfigured · modeled" as const,
    releaseSha: undefined,
    verificationChainReleaseSha: undefined,
  });
}
