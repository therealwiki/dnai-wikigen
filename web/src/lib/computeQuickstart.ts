const PROJECT_ID = /^[a-z][a-z0-9_]{2,63}$/;

export interface ComputeQuickstartInput {
  delegateUrl: string;
  projectId: string;
}

function normalizedDelegateUrl(value: string): string {
  const candidate = value.trim();
  if (!candidate || candidate.length > 2_048 || /[\s'"\\]/.test(candidate)) {
    throw new Error("Compute proxy origin is not safe for a shell quickstart");
  }
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Compute proxy origin is not a valid URL");
  }
  const localDevelopment = parsed.protocol === "http:"
    && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  if (
    (parsed.protocol !== "https:" && !localDevelopment)
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
  ) {
    throw new Error("Compute proxy origin must be HTTPS without credentials, query, or fragment");
  }
  return parsed.toString().replace(/\/$/, "");
}

/**
 * Build a deliberately non-mutating credential smoke test. The one-time token
 * is never interpolated into this string: the operator must paste it into the
 * shell environment separately, keeping examples and source history secret-free.
 */
export function computeCredentialQuickstart(input: ComputeQuickstartInput): string {
  const delegateUrl = normalizedDelegateUrl(input.delegateUrl);
  const projectId = input.projectId.trim();
  if (!PROJECT_ID.test(projectId)) {
    throw new Error("Compute project id is not safe for a shell quickstart");
  }
  return [
    `export WIKIGEN_API_URL='${delegateUrl}'`,
    `export WIKIGEN_PROJECT_ID='${projectId}'`,
    "export WIKIGEN_TOKEN='<paste-the-one-time-token-here>'",
    "",
    "# Read bounded job metadata. This does not create, dispatch, or charge a job.",
    "curl --fail-with-body --silent --show-error \\",
    "  -H 'Accept: application/json' \\",
    "  -H \"Authorization: Bearer ${WIKIGEN_TOKEN}\" \\",
    "  \"${WIKIGEN_API_URL}/compute/projects/${WIKIGEN_PROJECT_ID}/jobs\"",
  ].join("\n");
}
