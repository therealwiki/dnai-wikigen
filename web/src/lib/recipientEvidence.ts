import { recoverMessageAddress, type Hex } from "viem";

export type RecipientContext = "artifact" | "arena";
type RecordValue = Record<string, unknown>;
const encoder = new TextEncoder();
const HEX32 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
const TRUST_KEYS = ["schema", "context", "profile", "domain", "chain_id", "cvm_id", "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256", "release_policy_hash", "verifier_address", "signer_address", "contract_address", "compose_hash", "app_id", "os_image_hash", "encryption_public_key", "key_id", "report_data", "max_verdict_age_seconds"] as const;
const CHALLENGE_KEYS = ["schema", "chain_id", "domain", "profile", "cvm_id", "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256", "release_policy_hash", "challenge_id", "challenge_digest", "issued_at", "expires_at", "verifier_address", "verifier_signature"] as const;
const VERDICT_KEYS = ["schema", "verification_method", "verified", "chain_id", "domain", "profile", "cvm_id", "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256", "release_policy_hash", "challenge_id", "challenge_digest", "challenge_issued_at", "challenge_expires_at", "quote_hash", "report_data", "compose_hash", "app_id", "os_image_hash", "signer_address", "contract_address", "issued_at", "activation_evidence_lease_expires_at", "expires_at", "verifier_address", "verifier_signature"] as const;
const ROOT_KEYS = ["chain_id", "domain", "profile", "cvm_id", "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256", "release_policy_hash", "verifier_address"] as const;

export interface RecipientTrustPolicy {
  readonly schema: "dnai.recipient-trust-policy.v1";
  readonly context: RecipientContext;
  readonly profile: "artifact_recipient" | "arena";
  readonly domain: "main_runtime_cvm";
  readonly chain_id: 84532;
  readonly cvm_id: string;
  readonly deployment_intent_sha256: string;
  readonly release_authority_sha256: string;
  readonly ceremony_nonce: string;
  readonly measurement_policy_sha256: string;
  readonly release_policy_hash: string;
  readonly verifier_address: string;
  readonly signer_address: string;
  readonly contract_address: string;
  readonly compose_hash: string;
  readonly app_id: string;
  readonly os_image_hash: string;
  readonly encryption_public_key: string;
  readonly key_id: string;
  readonly report_data: string;
  readonly max_verdict_age_seconds: number;
}

export interface AuthenticatedRecipientEvidence {
  readonly context: RecipientContext;
  readonly recipient: Readonly<{ encryption_public_key: string; key_id: string; report_context: RecipientContext; report_data: string }>;
  readonly quoteDigest: `sha256:${string}`;
  readonly expiresAt: number;
  readonly issuedAt: number;
}

export interface RecipientDeploymentBinding {
  readonly schema: "dnai.recipient-deployment-binding.v1";
  readonly release_sha: string;
  readonly delegate_url: string;
  readonly deployment_intent_sha256: string;
  readonly release_authority_sha256: string;
  readonly ceremony_nonce: string;
}

export function parseRecipientDeploymentBinding(value: string | undefined): RecipientDeploymentBinding | undefined {
  if (!value?.trim()) return undefined;
  if (value.length > 4096) fail("deployment binding is oversized");
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { fail("deployment binding is not JSON"); }
  const binding = object(parsed, ["schema", "release_sha", "delegate_url", "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce"], "deployment binding");
  if (binding.schema !== "dnai.recipient-deployment-binding.v1") fail("deployment binding schema is invalid");
  matches(binding.release_sha, /^(?!0{40}$)[0-9a-f]{40}$/, "source release");
  matches(binding.deployment_intent_sha256, SHA256, "deployment intent");
  matches(binding.release_authority_sha256, SHA256, "release authority");
  matches(binding.ceremony_nonce, BYTES32, "ceremony nonce");
  if (typeof binding.delegate_url !== "string" || binding.delegate_url.length > 2048) fail("delegate URL is invalid");
  let url: URL;
  try { url = new URL(binding.delegate_url as string); } catch { fail("delegate URL is invalid"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) fail("delegate URL is invalid");
  return Object.freeze({ ...binding }) as unknown as RecipientDeploymentBinding;
}

export function assertRecipientTrustMatchesDeployment(trust: RecipientTrustPolicy, deployment: {
  releaseSha?: string; delegateUrl: string; cvmId: string; appId: string;
  composeHash: string; osImageHash: string; teeIdentity?: string;
  contractAddress?: string; challengeRegistryAddress?: string;
  attestationVerifierAddress?: string; attestationReleasePolicyHash?: string;
  recipientDeploymentBinding?: RecipientDeploymentBinding;
}): void {
  const binding = deployment.recipientDeploymentBinding;
  const contract = trust.context === "artifact" ? deployment.contractAddress : deployment.challengeRegistryAddress;
  if (!binding || binding.release_sha !== deployment.releaseSha
    || binding.delegate_url !== deployment.delegateUrl
    || binding.deployment_intent_sha256 !== trust.deployment_intent_sha256
    || binding.release_authority_sha256 !== trust.release_authority_sha256
    || binding.ceremony_nonce !== trust.ceremony_nonce
    || trust.cvm_id !== deployment.cvmId || trust.app_id !== deployment.appId
    || trust.compose_hash !== `0x${deployment.composeHash}`
    || trust.os_image_hash !== deployment.osImageHash
    || trust.signer_address !== deployment.teeIdentity?.toLowerCase()
    || trust.contract_address !== contract?.toLowerCase()
    || (trust.context === "artifact" && (
      trust.verifier_address !== deployment.attestationVerifierAddress?.toLowerCase()
      || trust.release_policy_hash !== deployment.attestationReleasePolicyHash?.toLowerCase()
    ))) fail("trust does not match the current browser deployment");
}
const authenticated = new WeakSet<object>();

function fail(detail: string): never { throw new Error(`Recipient evidence ${detail}`); }
function object(value: unknown, keys: readonly string[], label: string): RecordValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is invalid`);
  const record = value as RecordValue;
  if (Object.keys(record).length !== keys.length || keys.some((key) => !Object.hasOwn(record, key))) fail(`${label} fields are invalid`);
  return record;
}
function matches(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${label} is invalid`);
  return value as string;
}
function integer(value: unknown, label: string, maximum = 4_102_444_800): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) fail(`${label} is invalid`);
  return Number(value);
}
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as RecordValue;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}
function bytes(value: string): Uint8Array {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  return Uint8Array.from(hex.match(/../g) ?? [], (part) => Number.parseInt(part, 16));
}
function hex(value: Uint8Array): string { return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
async function digest(value: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", value.slice().buffer as ArrayBuffer)));
}
async function signedDigest(domain: string, payload: RecordValue, omitted: readonly string[]): Promise<Hex> {
  const body = Object.fromEntries(Object.entries(payload).filter(([key]) => !omitted.includes(key)));
  return `0x${await digest(encoder.encode(`${domain}\0${canonical(body)}`))}`;
}
async function authenticateSignature(payload: RecordValue, message: Hex, verifier: string): Promise<void> {
  const signature = matches(payload.verifier_signature, SIGNATURE, "signature") as Hex;
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const recovery = Number.parseInt(signature.slice(130), 16);
  if (s === 0n || s > HALF_ORDER || ![27, 28].includes(recovery)) fail("signature is not canonical");
  let recovered: string;
  try { recovered = (await recoverMessageAddress({ message: { raw: message }, signature })).toLowerCase(); }
  catch { fail("signature is invalid"); }
  if (recovered !== verifier) fail("signature is not from the approved independent verifier");
}

export function parseRecipientTrustPolicy(value: unknown, context: RecipientContext): RecipientTrustPolicy {
  const p = object(value, TRUST_KEYS, "trust policy");
  if (p.schema !== "dnai.recipient-trust-policy.v1" || p.context !== context || p.profile !== (context === "artifact" ? "artifact_recipient" : "arena") || p.domain !== "main_runtime_cvm" || p.chain_id !== 84532) fail("trust context is invalid");
  matches(p.cvm_id, /^[a-z0-9][a-z0-9._:-]{7,127}$/, "CVM id");
  for (const key of ["deployment_intent_sha256", "release_authority_sha256", "measurement_policy_sha256", "key_id"]) matches(p[key], SHA256, key);
  for (const key of ["ceremony_nonce", "release_policy_hash", "compose_hash", "report_data"]) matches(p[key], BYTES32, key);
  for (const key of ["verifier_address", "signer_address", "contract_address"]) matches(p[key], ADDRESS, key);
  if (p.verifier_address === p.signer_address || p.verifier_address === p.contract_address) fail("verifier is not purpose separated");
  matches(p.app_id, /^(?!0{40}$)[0-9a-f]{40}$/, "app id");
  matches(p.os_image_hash, HEX32, "OS image");
  matches(p.encryption_public_key, HEX32, "public key");
  integer(p.max_verdict_age_seconds, "maximum verdict age", 900);
  return Object.freeze({ ...p }) as unknown as RecipientTrustPolicy;
}

export function parseRecipientTrustConfiguration(value: string | undefined, context: RecipientContext): RecipientTrustPolicy | undefined {
  if (!value?.trim()) return undefined;
  if (value.length > 8192) fail("trust configuration is oversized");
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { fail("trust configuration is not JSON"); }
  return parseRecipientTrustPolicy(parsed, context);
}

export async function recipientKeyBinding(context: RecipientContext, publicKey: string): Promise<{ keyId: string; reportData: string }> {
  matches(publicKey, HEX32, "public key");
  const keyId = `sha256:${await digest(bytes(publicKey))}`;
  const payload = context === "artifact"
    ? { context, encryption_public_key: publicKey, service: "tinker-delegate" }
    : { context, encryption_public_key: publicKey, key_id: keyId, protocol: "arena_candidate_ingress_v1", service: "dnai-wikigen" };
  return { keyId, reportData: await digest(encoder.encode(canonical(payload))) };
}

/** Structural TDX-v4 report extraction only; independent signed QVL is mandatory. */
function actualQuoteReportData(quote: Uint8Array): string {
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  if (quote.length < 1024 || quote.length > 16 * 1024 || view.getUint16(0, true) !== 4 || view.getUint32(4, true) !== 0x81) fail("quote is not the supported bounded TDX-v4 format");
  return `0x${hex(quote.subarray(568, 632))}`;
}

export async function authenticateRecipientEvidence(raw: unknown, policy: RecipientTrustPolicy, now = Math.floor(Date.now() / 1000)): Promise<AuthenticatedRecipientEvidence> {
  const trust = parseRecipientTrustPolicy(policy, policy.context);
  integer(now, "clock");
  const envelope = object(raw, ["schema", "context", "recipient", "quote", "quote_report_data", "challenge", "verdict"], "envelope");
  if (envelope.schema !== "dnai.recipient-evidence.v1" || envelope.context !== trust.context) fail("envelope context mismatch");
  const recipient = object(envelope.recipient, ["encryption_public_key", "key_id", "report_context", "report_data"], "recipient");
  const key = recipient.encryption_public_key;
  if (key !== trust.encryption_public_key || recipient.report_context !== trust.context || recipient.key_id !== trust.key_id || `0x${recipient.report_data}` !== trust.report_data) fail("recipient differs from the approved release");
  const binding = await recipientKeyBinding(trust.context, String(key));
  if (binding.keyId !== trust.key_id || `0x${binding.reportData}` !== trust.report_data) fail("public key is not bound to the approved static report");
  const challenge = object(envelope.challenge, CHALLENGE_KEYS, "challenge");
  const verdict = object(envelope.verdict, VERDICT_KEYS, "verdict");
  if (challenge.schema !== "dnai.attestation-qvl-challenge.v2" || verdict.schema !== "dnai.independent-tdx-verdict.v4" || verdict.verification_method !== "intel_tdx_dcap_qvl" || verdict.verified !== true) fail("independent protocol version mismatch");
  for (const field of ROOT_KEYS) if (challenge[field] !== trust[field] || verdict[field] !== trust[field]) fail(`release ${field} mismatch`);
  for (const field of ["report_data", "compose_hash", "app_id", "os_image_hash", "signer_address", "contract_address"] as const) if (verdict[field] !== trust[field]) fail(`verdict ${field} mismatch`);
  matches(challenge.challenge_id, BYTES32, "challenge id");
  matches(challenge.challenge_digest, BYTES32, "challenge digest");
  const challengeIssued = integer(challenge.issued_at, "challenge issuance");
  const challengeExpires = integer(challenge.expires_at, "challenge expiry");
  const issuedAt = integer(verdict.issued_at, "verdict issuance");
  const expiresAt = integer(verdict.expires_at, "verdict expiry");
  if (challengeIssued > now + 5 || challengeExpires <= challengeIssued || challengeExpires - challengeIssued > 120 || issuedAt < challengeIssued || issuedAt >= challengeExpires || issuedAt > now + 5 || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt > trust.max_verdict_age_seconds || now - issuedAt > trust.max_verdict_age_seconds || verdict.activation_evidence_lease_expires_at !== expiresAt || verdict.challenge_id !== challenge.challenge_id || verdict.challenge_digest !== challenge.challenge_digest || verdict.challenge_issued_at !== challengeIssued || verdict.challenge_expires_at !== challengeExpires) fail("challenge or verdict lease is stale or invalid");
  const challengeDigest = await signedDigest("dnai-wikigen/attestation-qvl/challenge/v2", challenge, ["challenge_digest", "verifier_signature"]);
  if (challengeDigest !== challenge.challenge_digest) fail("challenge digest mismatch");
  await authenticateSignature(challenge, challengeDigest, trust.verifier_address);
  const quoteHex = matches(envelope.quote, /^0x[0-9a-f]+$/, "quote");
  if (quoteHex.length % 2 || quoteHex.length > 2 + 16384 * 2) fail("quote length is invalid");
  const quote = bytes(quoteHex);
  const expectedReport = `${trust.report_data}${challengeDigest.slice(2)}`;
  let quoteHash: string;
  try {
    if (envelope.quote_report_data !== expectedReport || actualQuoteReportData(quote) !== expectedReport) fail("actual quote report data does not match the authenticated recipient and challenge");
    quoteHash = await digest(quote);
  } finally { quote.fill(0); }
  if (verdict.quote_hash !== `0x${quoteHash}`) fail("actual quote hash differs from the independent verdict");
  await authenticateSignature(verdict, await signedDigest("dnai-wikigen/independent-tdx-verdict/v4", verdict, ["verifier_signature"]), trust.verifier_address);
  const result: AuthenticatedRecipientEvidence = Object.freeze({ context: trust.context, recipient: Object.freeze({ encryption_public_key: trust.encryption_public_key, key_id: trust.key_id, report_context: trust.context, report_data: binding.reportData }), quoteDigest: `sha256:${quoteHash}`, expiresAt, issuedAt });
  authenticated.add(result);
  return result;
}

export function requireFreshRecipientEvidence(evidence: AuthenticatedRecipientEvidence, now = Math.floor(Date.now() / 1000)): void {
  if (!authenticated.has(evidence) || !Number.isSafeInteger(now) || now < evidence.issuedAt - 5 || now >= evidence.expiresAt) fail("lease expired; renew independent evidence before sending ciphertext");
}
