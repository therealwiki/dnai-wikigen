import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256, type Hex } from "viem";
import { deployment } from "../config";
import fixture from "./fixtures/recipient-evidence-artifact.json";
import { ARTIFACT_COMMITMENT_SCHEME, ARTIFACT_ENVELOPE_SCHEME, ARTIFACT_PADDING_PROFILE, createArtifactRecoveryReceipt, uploadEncryptedArtifact } from "./artifact";
import { parseRecipientDeploymentBinding, parseRecipientTrustPolicy } from "./recipientEvidence";

const bytes = new TextEncoder().encode("synthetic private artifact fixture");
const originals = new Map<string, unknown>();
function setDeployment(values: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(values)) {
    if (!originals.has(key)) originals.set(key, (deployment as unknown as Record<string, unknown>)[key]);
    Object.defineProperty(deployment, key, { value, configurable: true });
  }
}
function configure(): void {
  setDeployment({
    artifactUploadEnabled: true, delegateUrl: "https://delegate.test", releaseSha: "a".repeat(40),
    contractAddress: fixture.trust.contract_address, teeIdentity: fixture.trust.signer_address,
    cvmId: fixture.trust.cvm_id, appId: fixture.trust.app_id,
    composeHash: fixture.trust.compose_hash.slice(2), osImageHash: fixture.trust.os_image_hash,
    attestationVerifierAddress: fixture.trust.verifier_address,
    attestationReleasePolicyHash: fixture.trust.release_policy_hash,
    artifactRecipientTrust: parseRecipientTrustPolicy(fixture.trust, "artifact"),
    recipientDeploymentBinding: parseRecipientDeploymentBinding(JSON.stringify({
      schema: "dnai.recipient-deployment-binding.v1", release_sha: "a".repeat(40),
      delegate_url: "https://delegate.test", deployment_intent_sha256: fixture.trust.deployment_intent_sha256,
      release_authority_sha256: fixture.trust.release_authority_sha256, ceremony_nonce: fixture.trust.ceremony_nonce,
    })),
  });
}
async function upload() {
  const receipt = createArtifactRecoveryReceipt(bytes);
  return uploadEncryptedArtifact(new File([bytes], "synthetic.txt"), receipt, "42", "synthetic-wallet-session", receipt.artifact_commitment, `0x${"44".repeat(32)}`);
}
afterEach(() => {
  for (const [key, value] of originals) Object.defineProperty(deployment, key, { value, configurable: true });
  originals.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("artifact upload renewable recipient integration", () => {
  it("encrypts using authenticated producer evidence and POSTs only ciphertext", async () => {
    configure();
    vi.spyOn(Date, "now").mockReturnValue(fixture.now * 1000);
    const fetch = vi.fn(async (url: string, request?: RequestInit) => {
      if (url.endsWith("/attestation/recipient?context=artifact")) return new Response(JSON.stringify(fixture.evidence));
      expect(url).toBe("https://delegate.test/deal/42/artifact/encrypted");
      expect(request?.method).toBe("POST");
      expect(String(request?.body)).not.toContain("synthetic private artifact");
      const payload = JSON.parse(String(request?.body));
      return new Response(JSON.stringify({
        deal_id: "42", received: true, ciphertext_sha256: `sha256:${sha256(`0x${payload.ciphertext}` as Hex).slice(2)}`,
        commitment_scheme: ARTIFACT_COMMITMENT_SCHEME, envelope_scheme: ARTIFACT_ENVELOPE_SCHEME,
        padding_profile: ARTIFACT_PADDING_PROFILE, exact_plaintext_size_egress: false,
      }));
    });
    vi.stubGlobal("fetch", fetch);
    await expect(upload()).resolves.toMatchObject({ received: true });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("blocks a valid other-deployment trust pair before any evidence fetch or encryption", async () => {
    configure();
    setDeployment({ contractAddress: `0x${"99".repeat(20)}` });
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(upload()).rejects.toThrow(/current browser deployment/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("checks the lease again after encryption and never POSTs expired evidence", async () => {
    configure();
    let now = fixture.now;
    vi.spyOn(Date, "now").mockImplementation(() => now * 1000);
    const fetch = vi.fn(async () => new Response(JSON.stringify(fixture.evidence)));
    vi.stubGlobal("fetch", fetch);
    const original = crypto.subtle.encrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => {
      const output = await original(...args);
      now = fixture.evidence.verdict.expires_at;
      return output;
    });
    await expect(upload()).rejects.toThrow(/lease expired/);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
