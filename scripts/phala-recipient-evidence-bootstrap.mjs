import { createHash } from "node:crypto";
import https from "node:https";
import { TextDecoder } from "node:util";
import { assertCanonicalPlainDataGraph, deepFreezeCanonicalPlainDataGraph } from "./canonical-authority-graph.mjs";
import { verifyIndependentEip191RawDigestSignature } from "./release-authority-signature-verifier-core.mjs";
import { readExactBoundPhaseSecretInputFile } from "./phala-production-environment-authority.mjs";
import { parseExactPublicHttpsUrl } from "../web/scripts/public-https-origin-core.mjs";

const EVIDENCE = new WeakMap();
const TOKEN_KEYS = Object.freeze({ artifact: "TINKER_ARTIFACT_RECIPIENT_QVL_AUTH_TOKEN", arena: "TINKER_ARENA_RECIPIENT_QVL_AUTH_TOKEN" });
const ROOT_KEYS = ["chain_id", "domain", "profile", "cvm_id", "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256", "release_policy_hash", "verifier_address"];
const CHALLENGE_KEYS = ["schema", ...ROOT_KEYS, "challenge_id", "challenge_digest", "issued_at", "expires_at", "verifier_signature"];
const VERDICT_KEYS = ["schema", "verification_method", "verified", ...ROOT_KEYS, "challenge_id", "challenge_digest", "challenge_issued_at", "challenge_expires_at", "quote_hash", "report_data", "compose_hash", "app_id", "os_image_hash", "signer_address", "contract_address", "issued_at", "activation_evidence_lease_expires_at", "expires_at", "verifier_signature"];
const HEX32 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const MAX_RESPONSE_BYTES = 96 * 1024;
const MAX_VERDICT_AGE = 900;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

function fail(stage) { throw new Error(`recipient bootstrap ${stage} failed closed; no automatic retry; use the explicit completed-launch recovery workflow`); }
function exact(value, fields, stage) {
  assertCanonicalPlainDataGraph(value, { label: "recipient bootstrap response" });
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) fail(stage);
  return value;
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
}
function json(value) { return JSON.stringify(canonical(value)); }
function sha(value) { return createHash("sha256").update(value).digest("hex"); }
function signedDigest(domain, value, omitted) {
  return `0x${sha(Buffer.from(`${domain}\0${json(Object.fromEntries(Object.entries(value).filter(([key]) => !omitted.includes(key))))}`, "ascii"))}`;
}
function currentSecond() { return Math.floor(Date.now() / 1_000); }
function integer(value) { return Number.isSafeInteger(value) && value > 0; }
function endpoint(value, suffix) {
  let url;
  if (typeof value !== "string" || value.length > 2_048) fail("reviewed endpoint");
  try { url = parseExactPublicHttpsUrl(value, "recipient bootstrap endpoint"); } catch { fail("reviewed endpoint"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash
    || url.port === "80" || url.href !== value || url.pathname !== suffix) fail("reviewed endpoint");
  return url;
}
function parseResponse(bytes) {
  const text = UTF8.decode(bytes);
  if (/[^\x20-\x7e\r\n\t]/.test(text)) fail("response encoding");
  let compact = "", inside = false, escaped = false;
  for (const char of text) {
    if (inside || !/[\r\n\t ]/.test(char)) compact += char;
    if (inside && escaped) escaped = false;
    else if (inside && char === "\\") escaped = true;
    else if (char === '"') inside = !inside;
  }
  const value = JSON.parse(text);
  // FastAPI's bounded hex/ASCII DTOs round-trip exactly. This rejects duplicate
  // keys and alternate numeric/string encodings without trusting JSON.parse's
  // last-key-wins behavior.
  if (JSON.stringify(value) !== compact) fail("ambiguous response JSON");
  return value;
}
function postJson(url, body, token, deadlineMs) {
  const timeoutMs = Math.min(30_000, deadlineMs - Date.now());
  if (timeoutMs < 1) fail("request deadline");
  const bytes = Buffer.from(json(body), "ascii");
  return new Promise((resolve, reject) => {
    let complete = false;
    let timer;
    const finish = (error, value) => {
      if (complete) return;
      complete = true;
      clearTimeout(timer);
      bytes.fill(0);
      if (error) reject(new Error("recipient bootstrap HTTPS exchange failed"));
      else resolve(value);
    };
    const request = https.request(url, {
      method: "POST", agent: false, rejectUnauthorized: true,
      headers: {
        "Content-Type": "application/json", Accept: "application/json",
        "Accept-Encoding": "identity", "Content-Length": String(bytes.length),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      if (response.statusCode !== 200 || response.headers["content-encoding"]
        || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers["content-type"] ?? "")) {
        response.destroy(); finish(true); return;
      }
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) { response.destroy(); finish(true); }
        else chunks.push(chunk);
      });
      response.on("error", () => finish(true));
      response.on("aborted", () => finish(true));
      response.on("end", () => {
        const raw = Buffer.concat(chunks);
        try { finish(false, parseResponse(raw)); } catch { finish(true); }
        finally { raw.fill(0); for (const chunk of chunks) chunk.fill(0); }
      });
    });
    request.on("error", () => finish(true));
    timer = setTimeout(() => { request.destroy(); finish(true); }, timeoutMs);
    request.end(bytes);
  });
}
function authenticateChallenge(value, expected, now) {
  const challenge = exact(value, CHALLENGE_KEYS, "challenge schema");
  if (challenge.schema !== "dnai.attestation-qvl-challenge.v2"
    || ROOT_KEYS.some((key) => challenge[key] !== expected[key])
    || !BYTES32.test(challenge.challenge_id) || !BYTES32.test(challenge.challenge_digest)
    || !integer(challenge.issued_at) || !integer(challenge.expires_at)
    || challenge.issued_at > now + 5 || challenge.expires_at <= now
    || challenge.expires_at <= challenge.issued_at || challenge.expires_at - challenge.issued_at > 120) fail("challenge authority or freshness");
  const digest = signedDigest("dnai-wikigen/attestation-qvl/challenge/v2", challenge, ["challenge_digest", "verifier_signature"]);
  if (digest !== challenge.challenge_digest) fail("challenge digest");
  verifyIndependentEip191RawDigestSignature({ address: expected.verifier_address, digest, signature: challenge.verifier_signature });
  return challenge;
}
function authenticateQuote(value, expected, challenge) {
  const quote = exact(value, ["schema", "context", "recipient", "quote", "quote_hash", "quote_report_data", "compose_hash", "app_id", "os_image_hash", "verified"], "quote schema");
  const recipient = exact(quote.recipient, ["encryption_public_key", "key_id", "report_context", "report_data"], "recipient schema");
  if (quote.schema !== "dnai.recipient-quote.v1" || quote.context !== expected.context || quote.verified !== false
    || !HEX32.test(recipient.encryption_public_key) || recipient.report_context !== expected.context
    || typeof quote.quote !== "string" || !/^0x[0-9a-f]+$/.test(quote.quote)
    || quote.quote.length % 2 || quote.quote.length < 2 + 1024 * 2 || quote.quote.length > 2 + 16_384 * 2
    || quote.compose_hash !== expected.compose_hash || quote.app_id !== expected.app_id
    || quote.os_image_hash !== expected.os_image_hash) fail("actual recipient quote identity");
  const publicKey = recipient.encryption_public_key;
  const keyId = `sha256:${sha(Buffer.from(publicKey, "hex"))}`;
  const binding = expected.context === "artifact"
    ? { context: "artifact", encryption_public_key: publicKey, service: "tinker-delegate" }
    : { context: "arena", encryption_public_key: publicKey, key_id: keyId, protocol: "arena_candidate_ingress_v1", service: "dnai-wikigen" };
  const reportData = sha(Buffer.from(json(binding), "ascii"));
  const expectedReport = `0x${reportData}${challenge.challenge_digest.slice(2)}`;
  const raw = Buffer.from(quote.quote.slice(2), "hex");
  let digest;
  try {
    digest = sha(raw);
    if (raw.readUInt16LE(0) !== 4 || raw.readUInt32LE(4) !== 0x81
      || `0x${raw.subarray(568, 632).toString("hex")}` !== expectedReport) fail("actual TDX report data");
  } finally { raw.fill(0); }
  if (recipient.key_id !== keyId || recipient.report_data !== reportData
    || quote.quote_report_data !== expectedReport || quote.quote_hash !== `0x${digest}`) fail("actual key, static report, or quote digest");
  return { quote, recipient, reportData: `0x${reportData}`, quoteSha256: `sha256:${digest}`, quoteSize: (quote.quote.length - 2) / 2 };
}
function authenticateVerdict(value, expected, challenge, quote, now) {
  const verdict = exact(value, VERDICT_KEYS, "verdict schema");
  if (verdict.schema !== "dnai.independent-tdx-verdict.v4" || verdict.verification_method !== "intel_tdx_dcap_qvl" || verdict.verified !== true
    || ROOT_KEYS.some((key) => verdict[key] !== expected[key])
    || ["app_id", "compose_hash", "os_image_hash", "signer_address", "contract_address"].some((key) => verdict[key] !== expected[key])
    || verdict.quote_hash !== quote.quote.quote_hash || verdict.report_data !== quote.reportData
    || verdict.challenge_id !== challenge.challenge_id || verdict.challenge_digest !== challenge.challenge_digest
    || verdict.challenge_issued_at !== challenge.issued_at || verdict.challenge_expires_at !== challenge.expires_at
    || !integer(verdict.issued_at) || !integer(verdict.expires_at) || verdict.issued_at < challenge.issued_at
    || verdict.issued_at >= challenge.expires_at || verdict.issued_at > now + 5 || verdict.expires_at <= now
    || verdict.expires_at <= verdict.issued_at || verdict.expires_at - verdict.issued_at > MAX_VERDICT_AGE
    || verdict.activation_evidence_lease_expires_at !== verdict.expires_at) fail("independent verdict authority or freshness");
  const digest = signedDigest("dnai-wikigen/independent-tdx-verdict/v4", verdict, ["verifier_signature"]);
  verifyIndependentEip191RawDigestSignature({ address: expected.verifier_address, digest, signature: verdict.verifier_signature });
  return { verdict, digest };
}

/** No caller JSON, transport override, or existing TRUST_JSON can mint evidence. */
export async function collectPhalaRecipientBootstrapEvidence(input = {}) {
  const { authority } = exact(input, ["authority"], "input");
  const { readPhalaRecipientBootstrapAuthority } = await import("./phala-production-activation-coordinator.mjs");
  const initial = readPhalaRecipientBootstrapAuthority(authority);
  const binding = json(initial);
  const current = () => {
    const next = readPhalaRecipientBootstrapAuthority(authority);
    if (json(next) !== binding || Date.now() >= next.deadlineMs) fail("phase or lineage drift");
    return next;
  };
  let stage = "private dedicated credential read";
  let secrets;
  try {
    secrets = readExactBoundPhaseSecretInputFile(initial.finalPhaseInput, {
      expectedDomain: "main_runtime_cvm", expectedPhase: "final_authority_runtime",
      expectedBatchId: initial.batchId, expectedCvmLaunchIntentSha256: initial.cvmLaunchIntentSha256,
    });
    const delegate = endpoint(initial.delegateUrl.endsWith("/") ? initial.delegateUrl : `${initial.delegateUrl}/`, "/");
    const verifyUrls = Object.fromEntries(["artifact", "arena"].map((context) => [
      context, endpoint(initial.contexts[context].qvl_url, "/verify"),
    ]));
    if (Object.values(verifyUrls).some((url) => url.origin === delegate.origin)) fail("independent QVL endpoint separation");
    const entries = {};
    const observations = {};
    for (const context of ["artifact", "arena"]) {
      const expected = initial.contexts[context];
      const token = secrets.values[TOKEN_KEYS[context]];
      if (typeof token !== "string" || token.length < 32 || token.length > 4096 || /[^\x21-\x7e]/.test(token)
        || Object.entries(secrets.values).some(([key, value]) => key !== TOKEN_KEYS[context] && value === token)) fail("dedicated credential separation");
      const verifyUrl = verifyUrls[context];
      stage = `${context} challenge`;
      const request = {
        schema: "dnai.attestation-qvl-challenge-request.v2",
        ...Object.fromEntries(ROOT_KEYS.filter((key) => !["release_policy_hash", "verifier_address"].includes(key)).map((key) => [key, expected[key]])),
      };
      const challenge = authenticateChallenge(await postJson(new URL("/challenge", verifyUrl), request, token, current().deadlineMs), expected, currentSecond());
      current();
      stage = `${context} fixed-key quote`;
      const collected = await postJson(new URL("/attestation/recipient-quote", delegate), {
        context, challenge_digest: challenge.challenge_digest,
      }, null, Math.min(current().deadlineMs, challenge.expires_at * 1_000));
      current();
      authenticateChallenge(challenge, expected, currentSecond());
      const quote = authenticateQuote(collected, expected, challenge);
      stage = `${context} independent QVL verification`;
      const verdictResponse = await postJson(verifyUrl, {
        schema: "dnai.independent-tdx-verification-request.v2", challenge, quote: quote.quote.quote,
        expectation: {
          mode: "tdx", signer_address: expected.signer_address, chain_id: 84_532, contract_address: expected.contract_address,
          report_data: quote.reportData, quote_report_data: quote.quote.quote_report_data,
          quote_hash: quote.quote.quote_hash, quote_size: quote.quoteSize,
          compose_hash: expected.compose_hash, app_id: expected.app_id, os_image_hash: expected.os_image_hash, raw_secret_egress: false,
        },
      }, token, Math.min(current().deadlineMs, challenge.expires_at * 1_000));
      current();
      const authenticated = authenticateVerdict(verdictResponse, expected, challenge, quote, currentSecond());
      observations[context] = { expected, challenge, quote: collected, verdict: verdictResponse };
      entries[context] = {
        trust: {
          schema: "dnai.recipient-trust-policy.v1",
          ...Object.fromEntries(Object.entries(expected).filter(([key]) => key !== "qvl_url")),
          encryption_public_key: quote.recipient.encryption_public_key, key_id: quote.recipient.key_id,
          report_data: quote.reportData, max_verdict_age_seconds: MAX_VERDICT_AGE,
        },
        qvl_url: expected.qvl_url, quote_sha256: quote.quoteSha256, verdict_digest: authenticated.digest,
        expires_at: authenticated.verdict.expires_at,
      };
    }
    stage = "final evidence lease";
    const checked = current();
    const expiresAt = Math.min(entries.artifact.expires_at, entries.arena.expires_at, Math.floor(checked.deadlineMs / 1_000));
    if (expiresAt <= currentSecond()) fail(stage);
    const { expires_at: _artifactExpiry, ...artifact } = entries.artifact;
    const { expires_at: _arenaExpiry, ...arena } = entries.arena;
    const result = deepFreezeCanonicalPlainDataGraph({
      schema: "dnai.recipient-trust-projection.v1", release_sha: checked.releaseSha,
      deployment_intent_sha256: checked.contexts.artifact.deployment_intent_sha256,
      release_authority_sha256: checked.contexts.artifact.release_authority_sha256,
      ceremony_nonce: checked.contexts.artifact.ceremony_nonce,
      validated_at: currentSecond(), evidence_expires_at: expiresAt, artifact, arena,
    });
    EVIDENCE.set(result, {
      authority, readAuthority: readPhalaRecipientBootstrapAuthority, digest: sha(json(result)),
      verificationInputs: deepFreezeCanonicalPlainDataGraph({
        releaseSha: checked.releaseSha, ...observations,
        trustedVerifierAddresses: {
          artifact: checked.contexts.artifact.verifier_address,
          arena: checked.contexts.arena.verifier_address,
        },
      }),
    });
    return result;
  } catch { fail(stage); }
  finally { secrets = null; }
}

export function readPhalaRecipientBootstrapEvidence(value, { now } = {}) {
  const retained = value && EVIDENCE.get(value);
  if (!retained || retained.digest !== sha(json(value)) || !integer(now)
    || Math.abs(now - currentSecond()) > 5 || currentSecond() >= value.evidence_expires_at
    || now < value.validated_at - 5 || now >= value.evidence_expires_at) fail("evidence provenance or lease");
  retained.readAuthority(retained.authority);
  return value;
}

/** Raw appraisals cross into the pure verifier only while their phase is live. */
export function readPhalaRecipientBootstrapVerificationInputs(value, { now } = {}) {
  readPhalaRecipientBootstrapEvidence(value, { now });
  return deepFreezeCanonicalPlainDataGraph({ ...EVIDENCE.get(value).verificationInputs, now });
}
