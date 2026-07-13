/*
 * A tiny client for dstack-webhost's PUBLIC verifier endpoints.
 *
 * dstack-webhost (github.com/amiller/dstack-webhost) is a "personal Vercel for
 * attestable web apps" — a tee-daemon that hosts tenants inside a Phala Intel
 * TDX CVM and binds each project's source hash into a real TDX quote. Its
 * read-only verifier endpoints are public (RFC 0015) and serve
 * `Access-Control-Allow-Origin: *`, so a browser SPA can fetch a genuine
 * attestation cross-origin with no token — exactly what "attested" should mean.
 *
 * This is the real counterpart to this app's own illustrative attestations.
 */

/**
 * The REFERENCE daemon — amiller's public dstack-webhost demo. Always available
 * as a worked example even when this app is not itself hosted on a TEE.
 */
export const REFERENCE_DAEMON = "https://915c8197b20b831c52cf97a9fb7e2e104cdc6ae8-8080.dstack-pha-prod7.phala.network";
export const REFERENCE_PROJECTS = ["timelock", "aishley", "tinycloud", "probe"] as const;

/** Kept for the isolation-probe link. */
export const DAEMON_BASE = REFERENCE_DAEMON;

/** One thing this section can verify: a daemon base + a project on it. */
export type TeeTarget = {
  key: string;
  label: string;
  base: string;
  project: string;
  /** true => this app verifying ITSELF (self-hosted on a tee-daemon) */
  isSelf: boolean;
  /** true => a captured offline fixture exists for this target */
  hasFixture: boolean;
};

const SELF_URL = import.meta.env.VITE_TEE_DAEMON_URL;
const SELF_PROJECT = import.meta.env.VITE_TEE_PROJECT ?? "wikigen-gate";

/**
 * If this build was served FROM a tee-daemon (path mounted at /<project>/),
 * derive a same-origin self target — so a deployed build self-verifies even
 * when no VITE_TEE_DAEMON_URL was baked in. Excludes dev / GitHub Pages hosts.
 */
function sameOriginSelf(): { base: string; project: string } | null {
  if (typeof window === "undefined") return null;
  const { origin, pathname, protocol, hostname } = window.location;
  if (protocol !== "https:") return null;
  if (hostname === "localhost" || hostname === "127.0.0.1" || hostname.endsWith("github.io")) return null;
  const seg = pathname.split("/").filter(Boolean)[0];
  if (!seg || seg === "assets") return null;
  return { base: origin, project: seg };
}

/** Resolve the selectable targets: self (if any) first, then the reference demo. */
export function resolveTargets(): TeeTarget[] {
  const targets: TeeTarget[] = [];
  if (SELF_URL) {
    targets.push({
      key: "self",
      label: `${SELF_PROJECT} · this app`,
      base: SELF_URL.replace(/\/$/, ""),
      project: SELF_PROJECT,
      isSelf: true,
      hasFixture: false,
    });
  } else {
    const cand = sameOriginSelf();
    if (cand) {
      targets.push({
        key: "self",
        label: `${cand.project} · this app`,
        base: cand.base,
        project: cand.project,
        isSelf: true,
        hasFixture: false,
      });
    }
  }
  for (const p of REFERENCE_PROJECTS) {
    targets.push({
      key: p,
      label: `${p} · reference demo`,
      base: REFERENCE_DAEMON,
      project: p,
      isSelf: false,
      hasFixture: p === "timelock",
    });
  }
  return targets;
}

export type SubstrateClaim = {
  container_runtime: string;
  effective_runtime: string;
  isolation_modes: string[];
  deno_entry_shim_sha256: string;
  networks: string[];
};

export type SourceRef = {
  repo: string;
  ref: string;
  commit_sha: string;
  tree_hash: string;
  tree_hash_kind: string;
};

export type BindingQuote = {
  signature_chain: string[];
  pubkey: string;
};

export type VerificationBundle = {
  schema_version: string;
  platform_quote: {
    quote: string;
    event_log: string;
    report_data: string;
    vm_config: string; // stringified JSON
  };
  webhost_app_id: string;
  onchain: Record<string, unknown>;
  gateway: Record<string, unknown>;
  app: {
    project: string;
    source: SourceRef;
    image_digest: string;
    binding_quote: BindingQuote;
  };
};

export type ProjectInfo = {
  runtime: string;
  mode: string;
  public: boolean;
  source: string;
  commit_sha: string;
  tree_hash: string;
};

async function getJson<T>(url: string, timeoutMs = 12000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

export function fetchVerification(project: string, base = DAEMON_BASE): Promise<VerificationBundle> {
  return getJson<VerificationBundle>(`${base}/_api/verification/${encodeURIComponent(project)}`);
}

export function fetchSubstrate(base = DAEMON_BASE): Promise<SubstrateClaim> {
  return getJson<SubstrateClaim>(`${base}/_api/substrate`);
}

export function fetchProjects(base = DAEMON_BASE): Promise<Record<string, ProjectInfo>> {
  return getJson<Record<string, ProjectInfo>>(`${base}/`);
}

/** Best-effort parse of the os_image_hash out of the stringified vm_config. */
export function osImageHash(bundle: VerificationBundle): string | null {
  try {
    const cfg = JSON.parse(bundle.platform_quote.vm_config) as { os_image_hash?: string };
    return cfg.os_image_hash ?? null;
  } catch {
    return null;
  }
}
