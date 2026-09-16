import { describe, expect, it } from "vitest";
import arenaLibrarySource from "../lib/arena.ts?raw";
import arenaSource from "./Arena.tsx?raw";

describe("Arena ChallengeRegistry truth boundary", () => {
  it("labels the browser read as a proposal and the proxy check as independent", () => {
    expect(arenaSource).toContain("Browser registry preflight passed");
    expect(arenaSource).toContain("This browser observation is not authority.");
    expect(arenaSource).toContain("the proxy must independently re-read every field before persistence");
    expect(arenaSource).toContain("Queue acceptance never grants worker execution authorization");
    expect(arenaSource).toContain("RPC quorum and consensus proof were not established");
  });

  it("encodes browser-only preflight separately from positive proxy and negative worker claims", () => {
    expect(arenaLibrarySource).toContain('status: "browser_preflight_passed"');
    expect(arenaLibrarySource).toContain('verificationScope: "browser_only"');
    expect(arenaLibrarySource).toContain("proxyIndependentlyVerified: false");
    expect(arenaLibrarySource).toContain("workerAuthorized: false");
    expect(arenaLibrarySource).toContain("registryBrowserPreflight: ArenaChallengeRegistryBrowserPreflight");
    expect(arenaLibrarySource).toContain('status: "proxy_independently_verified_at_finalized_block"');
    expect(arenaLibrarySource).toContain("browser_preflight_accepted_as_authority: false");
    expect(arenaLibrarySource).toContain("proxy_registry_authorized: true");
    expect(arenaLibrarySource).toContain("worker_registry_authorized: false");
    expect(arenaLibrarySource).toContain("independent_rpc_quorum_verified: false");
    expect(arenaLibrarySource).toContain("consensus_proof_verified: false");
  });

  it("re-runs the local preflight and sends only an AEAD-bound proposed snapshot", () => {
    expect(arenaLibrarySource.match(/runArenaChallengeRegistryBrowserPreflight\(challenge\)/g)).toHaveLength(2);
    expect(arenaLibrarySource).toContain("sameArenaChallengeRegistryBrowserPreflight");
    expect(arenaLibrarySource).toContain("registry_authorization_sha256: registryAuthorizationSha256");
    expect(arenaLibrarySource).toContain("registry_authorization: registryAuthorization");
    expect(arenaLibrarySource).toContain("body: JSON.stringify(prepared.payload)");
    expect(arenaLibrarySource).not.toContain("registryBrowserPreflight: prepared.registryBrowserPreflight");
  });
});
