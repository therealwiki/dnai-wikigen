import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { sha256, stringToHex, type Hex } from "viem";
import artifactFixture from "./fixtures/recipient-evidence-artifact.json";
import arenaFixture from "./fixtures/recipient-evidence-arena.json";
import { authenticateRecipientEvidence, assertRecipientTrustMatchesDeployment, parseRecipientDeploymentBinding, parseRecipientTrustConfiguration, parseRecipientTrustPolicy, recipientKeyBinding, requireFreshRecipientEvidence, type RecipientContext } from "./recipientEvidence";

// These are exact outputs of the Python provider's synthetic, non-hardware
// harness. Python also compares its complete output to these shared files.
const fixtures = { artifact: artifactFixture, arena: arenaFixture };
const signer = privateKeyToAccount(`0x${"81".repeat(32)}`);
function canonical(value: unknown): string {
  if (!value || typeof value !== "object") return JSON.stringify(value);
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}
async function signVerdict(verdict: Record<string, unknown>): Promise<void> {
  const { verifier_signature: _signature, ...body } = verdict;
  verdict.verifier_signature = await signer.signMessage({ message: { raw: sha256(stringToHex(`dnai-wikigen/independent-tdx-verdict/v4\0${canonical(body)}`)) } });
}
function replaceQuoteBytes(quote: string, offset: number, value: string): string {
  const start = 2 + offset * 2;
  return quote.slice(0, start) + value + quote.slice(start + value.length);
}

describe.each(["artifact", "arena"] as const)("renewable %s recipient evidence", (context: RecipientContext) => {
  const fixture = fixtures[context];
  const policy = () => parseRecipientTrustPolicy(fixture.trust, context);
  const deployment = () => ({
    releaseSha: "a".repeat(40), delegateUrl: "https://delegate.test",
    cvmId: fixture.trust.cvm_id, appId: fixture.trust.app_id,
    composeHash: fixture.trust.compose_hash.slice(2), osImageHash: fixture.trust.os_image_hash,
    teeIdentity: fixture.trust.signer_address,
    contractAddress: fixture.trust.contract_address,
    challengeRegistryAddress: fixture.trust.contract_address,
    attestationVerifierAddress: fixture.trust.verifier_address,
    attestationReleasePolicyHash: fixture.trust.release_policy_hash,
    recipientDeploymentBinding: parseRecipientDeploymentBinding(JSON.stringify({
      schema: "dnai.recipient-deployment-binding.v1", release_sha: "a".repeat(40),
      delegate_url: "https://delegate.test",
      deployment_intent_sha256: fixture.trust.deployment_intent_sha256,
      release_authority_sha256: fixture.trust.release_authority_sha256,
      ceremony_nonce: fixture.trust.ceremony_nonce,
    })),
  });

  it("authenticates the exact Python-produced quote, signed challenge/verdict, and public recipient", async () => {
    expect(fixture.synthetic_non_authorizing).toBe(true);
    const result = await authenticateRecipientEvidence(fixture.evidence, policy(), fixture.now);
    expect(result.recipient).toEqual(fixture.evidence.recipient);
    expect(result.quoteDigest).toBe(`sha256:${fixture.evidence.verdict.quote_hash.slice(2)}`);
    expect(result.expiresAt).toBe(fixture.evidence.verdict.expires_at);
    expect(() => requireFreshRecipientEvidence(result, result.expiresAt - 1)).not.toThrow();
    expect(() => requireFreshRecipientEvidence(result, result.expiresAt)).toThrow(/lease expired/);
    expect(() => requireFreshRecipientEvidence({ ...result }, fixture.now)).toThrow(/lease expired/);
  });

  it("does not turn a consumed challenge into an expired verdict", async () => {
    const evidence = structuredClone(fixture.evidence);
    evidence.verdict.expires_at = fixture.now + 180;
    evidence.verdict.activation_evidence_lease_expires_at = fixture.now + 180;
    await signVerdict(evidence.verdict);
    await expect(authenticateRecipientEvidence(evidence, { ...policy(), max_verdict_age_seconds: 300 }, fixture.now + 100)).resolves.toMatchObject({ expiresAt: fixture.now + 180 });
  });

  it("accepts a newly authenticated Python-produced renewal after the previous lease expires", async () => {
    await expect(authenticateRecipientEvidence(fixture.evidence, policy(), fixture.renewed.now)).rejects.toThrow(/lease/);
    const renewed = await authenticateRecipientEvidence(fixture.renewed.evidence, policy(), fixture.renewed.now);
    expect(renewed.recipient).toEqual(fixture.evidence.recipient);
    expect(renewed.quoteDigest).not.toBe(`sha256:${fixture.evidence.verdict.quote_hash.slice(2)}`);
    expect(renewed.expiresAt).toBeGreaterThan(fixture.evidence.verdict.expires_at);
  });

  it("requires direct current-deployment agreement even for independently valid evidence", async () => {
    await expect(authenticateRecipientEvidence(fixture.evidence, policy(), fixture.now)).resolves.toBeDefined();
    expect(() => assertRecipientTrustMatchesDeployment(policy(), deployment())).not.toThrow();
    for (const field of ["releaseSha", "delegateUrl", "cvmId", "appId", "composeHash", "osImageHash", "teeIdentity", context === "artifact" ? "contractAddress" : "challengeRegistryAddress"] as const) {
      expect(() => assertRecipientTrustMatchesDeployment(policy(), { ...deployment(), [field]: "different-release" })).toThrow(/current browser deployment/);
    }
    for (const field of ["deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce"] as const) {
      const current = deployment();
      current.recipientDeploymentBinding = { ...current.recipientDeploymentBinding!, [field]: "different-release" };
      expect(() => assertRecipientTrustMatchesDeployment(policy(), current)).toThrow(/current browser deployment/);
    }
    expect(() => assertRecipientTrustMatchesDeployment(policy(), { ...deployment(), recipientDeploymentBinding: undefined })).toThrow(/current browser deployment/);
    if (context === "artifact") {
      for (const field of ["attestationVerifierAddress", "attestationReleasePolicyHash"] as const) {
        expect(() => assertRecipientTrustMatchesDeployment(policy(), { ...deployment(), [field]: "different-release" })).toThrow(/current browser deployment/);
      }
    }
  });

  it.each(["challenge", "verdict"] as const)("rejects a forged %s signature", async (field) => {
    const evidence = structuredClone(fixture.evidence);
    evidence[field].verifier_signature = `0x${"11".repeat(64)}1b`;
    await expect(authenticateRecipientEvidence(evidence, policy(), fixture.now)).rejects.toThrow(/signature/);
  });

  it.each(["profile", "release_authority_sha256", "measurement_policy_sha256", "cvm_id", "verifier_address"] as const)("rejects substituted %s roots", async (field) => {
    const evidence = structuredClone(fixture.evidence);
    evidence.verdict[field] = "wrong-release";
    await expect(authenticateRecipientEvidence(evidence, policy(), fixture.now)).rejects.toThrow(/mismatch/);
  });

  it("rejects a changed recipient after restart, including a matching unreviewed key/report pair", async () => {
    const evidence = structuredClone(fixture.evidence);
    const key = "35".repeat(32);
    const binding = await recipientKeyBinding(context, key);
    evidence.recipient = { encryption_public_key: key, key_id: binding.keyId, report_context: context, report_data: binding.reportData };
    await expect(authenticateRecipientEvidence(evidence, policy(), fixture.now)).rejects.toThrow(/recipient differs/);
    await expect(authenticateRecipientEvidence(fixture.evidence, { ...policy(), encryption_public_key: key }, fixture.now)).rejects.toThrow(/recipient differs/);
  });

  it("rejects an actual static/zero-upper quote even with an authentic signature over its hash", async () => {
    const evidence = structuredClone(fixture.evidence);
    evidence.quote = replaceQuoteBytes(evidence.quote, 600, "00".repeat(32));
    evidence.verdict.quote_hash = sha256(evidence.quote as Hex);
    await signVerdict(evidence.verdict);
    await expect(authenticateRecipientEvidence(evidence, policy(), fixture.now)).rejects.toThrow(/actual quote report data/);
  });

  it("rejects a forged adjacent report field, a changed actual quote, and unsupported quote formats", async () => {
    const metadata = structuredClone(fixture.evidence);
    metadata.quote_report_data = `0x${"ff".repeat(64)}`;
    await expect(authenticateRecipientEvidence(metadata, policy(), fixture.now)).rejects.toThrow(/actual quote report data/);
    const hash = structuredClone(fixture.evidence);
    hash.quote = replaceQuoteBytes(hash.quote, 700, "ff");
    await expect(authenticateRecipientEvidence(hash, policy(), fixture.now)).rejects.toThrow(/actual quote hash/);
    const format = structuredClone(fixture.evidence);
    format.quote = replaceQuoteBytes(format.quote, 0, "0500");
    await expect(authenticateRecipientEvidence(format, policy(), fixture.now)).rejects.toThrow(/TDX-v4/);
  });

  it("rejects expired and oversized leases and mismatched challenge commitments", async () => {
    await expect(authenticateRecipientEvidence(fixture.evidence, policy(), fixture.evidence.verdict.expires_at)).rejects.toThrow(/lease/);
    const lease = structuredClone(fixture.evidence);
    lease.verdict.expires_at = fixture.now + 901;
    lease.verdict.activation_evidence_lease_expires_at = fixture.now + 901;
    await expect(authenticateRecipientEvidence(lease, policy(), fixture.now)).rejects.toThrow(/lease/);
    const challenge = structuredClone(fixture.evidence);
    challenge.challenge.expires_at += 121;
    await expect(authenticateRecipientEvidence(challenge, policy(), fixture.now)).rejects.toThrow(/lease/);
  });

  it("rejects local verified flags, legacy envelopes, unexpected fields and missing trust", async () => {
    await expect(authenticateRecipientEvidence({ ...fixture.evidence, verified: true }, policy(), fixture.now)).rejects.toThrow(/fields/);
    await expect(authenticateRecipientEvidence({ mode: "tdx", ...fixture.evidence.recipient, quote: fixture.evidence.quote }, policy(), fixture.now)).rejects.toThrow(/fields/);
    expect(parseRecipientTrustConfiguration("", context)).toBeUndefined();
    expect(() => parseRecipientTrustConfiguration(JSON.stringify({ ...fixture.trust, arbitrary_authority: true }), context)).toThrow(/fields/);
    expect(() => parseRecipientTrustPolicy({ ...fixture.trust, max_verdict_age_seconds: 901 }, context)).toThrow(/maximum verdict age/);
  });
});

it("rejects the original diligence result-signer profile as artifact encryption authority", async () => {
  const evidence = structuredClone(artifactFixture.evidence);
  evidence.verdict.profile = "diligence";
  await signVerdict(evidence.verdict);
  await expect(authenticateRecipientEvidence(evidence, parseRecipientTrustPolicy(artifactFixture.trust, "artifact"), artifactFixture.now)).rejects.toThrow(/profile mismatch/);
});
