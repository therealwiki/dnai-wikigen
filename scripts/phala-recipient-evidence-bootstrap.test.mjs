import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { readPhalaRecipientBootstrapAuthority } from "./phala-production-activation-coordinator.mjs";
import { collectPhalaRecipientBootstrapEvidence, readPhalaRecipientBootstrapEvidence, readPhalaRecipientBootstrapVerificationInputs } from "./phala-recipient-evidence-bootstrap.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const exec = promisify(execFile);
const HARNESS = String.raw`
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { mock } from "node:test";
import { pathToFileURL } from "node:url";
import path from "node:path";
import { privateKeyToAccount } from "./web/node_modules/viem/_esm/accounts/index.js";

const scenario = process.env.RECIPIENT_BOOTSTRAP_TEST;
const url = (name) => pathToFileURL(path.join(process.cwd(), name)).href;
const originalNow = Date.now;
const now = 2_000_000_000;
Date.now = () => now * 1000;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (value) => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
const json = (value) => JSON.stringify(canonical(value));
const digest = (domain, value, omitted) => "0x" + hash(Buffer.from(domain + "\0" + json(Object.fromEntries(Object.entries(value).filter(([key]) => !omitted.includes(key)))), "ascii"));
const word = (n) => "0x" + n.toString(16).padStart(2, "0").repeat(32);
const sha = (n) => "sha256:" + word(n).slice(2);
const address = (n) => "0x" + n.toString(16).padStart(40, "0");
// Deterministic, public test-only signers. No wallet/keystore or provider is used.
const accounts = { artifact: privateKeyToAccount(word(1)), arena: privateKeyToAccount(word(2)) };
const tokens = { artifact: "artifact-only-test-token-" + "a".repeat(32), arena: "arena-only-test-token-" + "b".repeat(32) };
const secretValues = {
  TINKER_ARTIFACT_RECIPIENT_QVL_AUTH_TOKEN: tokens.artifact,
  TINKER_ARENA_RECIPIENT_QVL_AUTH_TOKEN: tokens.arena,
  TINKER_DILIGENCE_QVL_AUTH_TOKEN: "existing-result-token-" + "c".repeat(32),
  TINKER_ARENA_WORKER_QVL_AUTH_TOKEN: "existing-worker-token-" + "d".repeat(32),
};
if (scenario === "token-reuse") secretValues.TINKER_ARTIFACT_RECIPIENT_QVL_AUTH_TOKEN = secretValues.TINKER_DILIGENCE_QVL_AUTH_TOKEN;
const authority = Object.freeze({ schema: "test-only-bootstrap-authority" });
let active = true;
const contexts = Object.fromEntries(["artifact", "arena"].map((context) => [context, {
  context, profile: context === "artifact" ? "artifact_recipient" : "arena",
  domain: "main_runtime_cvm", chain_id: 84532, cvm_id: "main-runtime-test-cvm",
  deployment_intent_sha256: sha(3), release_authority_sha256: sha(4), ceremony_nonce: word(5),
  measurement_policy_sha256: sha(context === "artifact" ? 6 : 7), release_policy_hash: word(context === "artifact" ? 8 : 9),
  verifier_address: accounts[context].address.toLowerCase(), signer_address: address(10), contract_address: address(context === "artifact" ? 11 : 12),
  compose_hash: word(13), app_id: "14".repeat(20), os_image_hash: word(15).slice(2),
  qvl_url: "https://" + context + ".qvl.wikigen.me/verify",
}]));
const bound = {
  releaseSha: "ab".repeat(20), batchId: "bootstrap-test-batch", cvmLaunchIntentSha256: sha(16),
  delegateUrl: "https://main.wikigen.me", finalPhaseInput: { path: "/test-only/final-phase.json", sha256: sha(17) },
  deadlineMs: (now + 600) * 1000, contexts,
};
const invalidEndpoints = {
  "endpoint-private-ip": "https://127.0.0.1:8443/verify",
  "endpoint-ipv6-loopback": "https://[::1]/verify",
  "endpoint-metadata-ip": "https://169.254.169.254/verify",
  "endpoint-private-dns": "https://qvl.internal/verify",
  "endpoint-reserved-dns": "https://qvl.example/verify",
  "endpoint-normalized-ip": "https://2130706433/verify",
  "endpoint-credentials": "https://secret@qvl.wikigen.me/verify",
  "endpoint-query": "https://qvl.wikigen.me/verify?token=ignored",
  "endpoint-wrong-path": "https://qvl.wikigen.me/other",
};
if (invalidEndpoints[scenario]) contexts.artifact.qvl_url = invalidEndpoints[scenario];
if (scenario === "endpoint-arena-private") contexts.arena.qvl_url = "https://192.168.1.1/verify";
if (scenario === "endpoint-main-private") bound.delegateUrl = "https://main.local";
if (scenario === "endpoint-main-is-qvl") bound.delegateUrl = "https://artifact.qvl.wikigen.me";
mock.module(url("scripts/phala-production-activation-coordinator.mjs"), { namedExports: {
  readPhalaRecipientBootstrapAuthority(value) {
    assert.equal(value, authority);
    if (!active) throw new Error("phase is no longer active");
    return bound;
  },
} });
mock.module(url("scripts/phala-production-environment-authority.mjs"), { namedExports: {
  readExactBoundPhaseSecretInputFile(binding, expected) {
    assert.deepEqual(binding, bound.finalPhaseInput);
    assert.deepEqual(expected, { expectedDomain: "main_runtime_cvm", expectedPhase: "final_authority_runtime", expectedBatchId: bound.batchId, expectedCvmLaunchIntentSha256: bound.cvmLaunchIntentSha256 });
    return { values: { ...secretValues } };
  },
} });
const calls = [];
const challenges = {};
const roots = ["chain_id", "domain", "profile", "cvm_id", "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256", "release_policy_hash", "verifier_address"];
async function responseFor(target, options, body) {
  const context = target.hostname.startsWith("artifact") ? "artifact" : target.hostname.startsWith("arena") ? "arena" : body.context;
  const expected = contexts[context];
  calls.push({ target: target.href, body, authorization: options.headers.Authorization });
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.agent, false);
  if (target.pathname !== "/attestation/recipient-quote") assert.equal(options.headers.Authorization, "Bearer " + tokens[context]);
  else {
    assert.equal(options.headers.Authorization, undefined);
    assert.deepEqual(Object.keys(body).sort(), ["challenge_digest", "context"]);
    assert.equal(body.challenge_digest, challenges[context].challenge_digest);
  }
  if (scenario === "redirect") return { statusCode: 302, body: { location: "https://evil.example" } };
  if (scenario === "service-failure") return { statusCode: 503, body: { error: tokens.artifact } };
  if (scenario === "oversize") return { text: JSON.stringify({ padding: "x".repeat(100_000) }) };
  if (target.pathname === "/challenge") {
    assert.equal(body.schema, "dnai.attestation-qvl-challenge-request.v2");
    assert.equal(body.profile, expected.profile);
    assert.equal(body.domain, "main_runtime_cvm");
    const result = { schema: "dnai.attestation-qvl-challenge.v2", ...Object.fromEntries(roots.map((key) => [key, expected[key]])), challenge_id: word(context === "artifact" ? 18 : 19), issued_at: now, expires_at: now + 60 };
    if (scenario === "wrong-purpose") result.profile = "diligence";
    if (scenario === "wrong-lineage") result.ceremony_nonce = word(90);
    if (scenario === "stale-challenge") { result.issued_at = now - 120; result.expires_at = now; }
    if (scenario === "long-challenge") result.expires_at = now + 121;
    result.challenge_digest = digest("dnai-wikigen/attestation-qvl/challenge/v2", result, []);
    result.verifier_signature = await accounts[scenario === "wrong-signer" ? "arena" : context].signMessage({ message: { raw: result.challenge_digest } });
    challenges[context] = result;
    if (scenario === "phase-after-challenge") active = false;
    if (scenario === "duplicate-json") return { text: JSON.stringify(result).replace('"schema":', '"schema":"ignored","schema":') };
    return { body: result };
  }
  if (target.pathname === "/attestation/recipient-quote") {
    const key = word(context === "artifact" ? 20 : 21).slice(2);
    const keyId = "sha256:" + hash(Buffer.from(key, "hex"));
    const binding = context === "artifact" ? { context, encryption_public_key: key, service: "tinker-delegate" }
      : { context, encryption_public_key: key, key_id: keyId, protocol: "arena_candidate_ingress_v1", service: "dnai-wikigen" };
    const report = hash(Buffer.from(json(binding), "ascii"));
    const reportBytes = report + body.challenge_digest.slice(2);
    const raw = Buffer.alloc(1024);
    raw.writeUInt16LE(4, 0); raw.writeUInt32LE(0x81, 4); Buffer.from(reportBytes, "hex").copy(raw, 568);
    const result = { schema: "dnai.recipient-quote.v1", context, recipient: { encryption_public_key: key, key_id: keyId, report_context: context, report_data: report }, quote: "0x" + raw.toString("hex"), quote_hash: "0x" + hash(raw), quote_report_data: "0x" + reportBytes, compose_hash: expected.compose_hash, app_id: expected.app_id, os_image_hash: expected.os_image_hash, verified: false };
    if (scenario === "wrong-key") result.recipient.encryption_public_key = word(99).slice(2);
    if (scenario === "wrong-report") result.quote_report_data = "0x" + "99".repeat(64);
    if (scenario === "raw-report-corrupt") { raw[568] ^= 1; result.quote = "0x" + raw.toString("hex"); result.quote_hash = "0x" + hash(raw); }
    if (scenario === "wrong-cvm") result.app_id = "99".repeat(20);
    if (scenario === "phase-after-quote") active = false;
    return { body: result };
  }
  assert.equal(target.pathname, "/verify");
  assert.equal(body.schema, "dnai.independent-tdx-verification-request.v2");
  assert.equal(body.expectation.raw_secret_egress, false);
  assert.equal(body.expectation.quote_size, 1024);
  const result = { schema: "dnai.independent-tdx-verdict.v4", verification_method: "intel_tdx_dcap_qvl", verified: true,
    ...Object.fromEntries(roots.map((key) => [key, expected[key]])),
    challenge_id: body.challenge.challenge_id, challenge_digest: body.challenge.challenge_digest,
    challenge_issued_at: body.challenge.issued_at, challenge_expires_at: body.challenge.expires_at,
    quote_hash: body.expectation.quote_hash, report_data: body.expectation.report_data,
    ...Object.fromEntries(["compose_hash", "app_id", "os_image_hash", "signer_address", "contract_address"].map((key) => [key, expected[key]])),
    issued_at: now, activation_evidence_lease_expires_at: now + 600, expires_at: now + 600 };
  if (scenario === "wrong-verdict-contract") result.contract_address = address(99);
  if (scenario === "wrong-verdict-policy") result.release_policy_hash = word(99);
  if (scenario === "wrong-verdict-quote") result.quote_hash = word(99);
  if (scenario === "expired-verdict") { result.expires_at = now; result.activation_evidence_lease_expires_at = now; }
  if (scenario === "long-verdict") { result.expires_at = now + 901; result.activation_evidence_lease_expires_at = now + 901; }
  const signed = digest("dnai-wikigen/independent-tdx-verdict/v4", result, []);
  result.verifier_signature = await accounts[scenario === "wrong-verdict-signer" ? "arena" : context].signMessage({ message: { raw: signed } });
  if (scenario === "phase-after-verdict") active = false;
  if (scenario === "partial-arena-failure" && context === "arena") return { statusCode: 503, body: {} };
  return { body: result };
}
mock.module("node:https", { defaultExport: { request(target, options, callback) {
  const request = new EventEmitter();
  request.destroy = () => {};
  request.end = (bytes) => {
    const body = JSON.parse(bytes.toString("ascii"));
    void responseFor(target, options, body).then((output) => {
      const response = new PassThrough();
      response.statusCode = output.statusCode ?? 200;
      response.headers = { "content-type": "application/json" };
      callback(response);
      response.end(Buffer.from(output.text ?? JSON.stringify(output.body), "ascii"));
    }).catch((error) => request.emit("error", error));
  };
  return request;
} } });
const bootstrap = await import(url("scripts/phala-recipient-evidence-bootstrap.mjs"));
if (scenario === "success") {
  const result = await bootstrap.collectPhalaRecipientBootstrapEvidence({ authority });
  assert.equal(calls.length, 6);
  assert.deepEqual(calls.map((entry) => new URL(entry.target).pathname), ["/challenge", "/attestation/recipient-quote", "/verify", "/challenge", "/attestation/recipient-quote", "/verify"]);
  assert.equal(result.artifact.trust.profile, "artifact_recipient");
  assert.equal(result.arena.trust.profile, "arena");
  assert.equal(result.evidence_expires_at, now + 600);
  assert.equal(bootstrap.readPhalaRecipientBootstrapEvidence(result, { now }), result);
  assert.throws(() => bootstrap.readPhalaRecipientBootstrapEvidence(structuredClone(result), { now }), /provenance/);
  const release = await import(url("web/scripts/release-env-core.mjs"));
  const verificationInputs = bootstrap.readPhalaRecipientBootstrapVerificationInputs(result, { now });
  assert.deepEqual(Object.keys(verificationInputs).sort(), ["arena", "artifact", "now", "releaseSha", "trustedVerifierAddresses"]);
  assert.equal(verificationInputs.artifact.expected, contexts.artifact);
  assert.equal(verificationInputs.artifact.challenge.profile, "artifact_recipient");
  assert.equal(verificationInputs.artifact.quote.verified, false);
  const projected = await release.createRecipientTrustProjectionFromBootstrapEvidence(verificationInputs);
  assert.deepEqual(projected, result);
  assert.equal(release.readRecipientTrustProjection(projected, { now }), projected);
  assert.throws(() => release.readRecipientTrustProjection(structuredClone(projected), { now }), /provenance/);
  assert.throws(() => bootstrap.readPhalaRecipientBootstrapEvidence(result, { now: now + 600 }), /lease/);
  Date.now = () => (now + 600) * 1000;
  assert.throws(() => bootstrap.readPhalaRecipientBootstrapVerificationInputs(result, { now }), /lease/);
  Date.now = () => now * 1000;
  active = false;
  assert.throws(() => bootstrap.readPhalaRecipientBootstrapEvidence(result, { now }), /phase/);
  assert.throws(() => bootstrap.readPhalaRecipientBootstrapVerificationInputs(result, { now }), /phase/);
  assert.ok(!JSON.stringify(result).includes(tokens.artifact));
} else {
  let failure;
  try { await bootstrap.collectPhalaRecipientBootstrapEvidence({ authority }); } catch (error) { failure = error; }
  assert.ok(failure, scenario + " must fail");
  assert.match(failure.message, /failed closed; no automatic retry/);
  assert.ok(!failure.message.includes(tokens.artifact));
  const expected = scenario === "token-reuse" || scenario.startsWith("endpoint-") ? 0 : scenario === "partial-arena-failure" ? 6
    : ["wrong-key", "wrong-report", "raw-report-corrupt", "wrong-cvm", "phase-after-quote"].includes(scenario) ? 2
      : ["wrong-verdict-contract", "wrong-verdict-policy", "wrong-verdict-quote", "wrong-verdict-signer", "expired-verdict", "long-verdict", "phase-after-verdict"].includes(scenario) ? 3 : 1;
  assert.equal(calls.length, expected, "failed phase must never advance or retry");
}
Date.now = originalNow;
console.log("verified " + scenario);
`;

test("recipient bootstrap rejects unbranded authority/evidence before network access", async () => {
  assert.throws(() => readPhalaRecipientBootstrapAuthority({}), /exact active coordinator/);
  assert.throws(() => readPhalaRecipientBootstrapEvidence({}, { now: 2_000_000_000 }), /provenance/);
  assert.throws(() => readPhalaRecipientBootstrapVerificationInputs({}, { now: 2_000_000_000 }), /provenance/);
  await assert.rejects(collectPhalaRecipientBootstrapEvidence({ authority: {} }), /exact active coordinator/);
  await assert.rejects(collectPhalaRecipientBootstrapEvidence({ authority: {}, fetch: () => {} }), /canonical|input|JSON|data/i);
});

for (const scenario of [
  "success", "wrong-purpose", "wrong-lineage", "wrong-signer", "stale-challenge", "long-challenge",
  "wrong-key", "wrong-report", "raw-report-corrupt", "wrong-cvm", "wrong-verdict-contract", "wrong-verdict-policy",
  "wrong-verdict-quote", "wrong-verdict-signer", "expired-verdict", "long-verdict", "phase-after-challenge",
  "phase-after-quote", "phase-after-verdict", "partial-arena-failure", "redirect", "service-failure", "oversize", "duplicate-json", "token-reuse",
  "endpoint-private-ip", "endpoint-ipv6-loopback", "endpoint-metadata-ip", "endpoint-private-dns", "endpoint-reserved-dns",
  "endpoint-normalized-ip", "endpoint-credentials", "endpoint-query", "endpoint-wrong-path", "endpoint-arena-private", "endpoint-main-private", "endpoint-main-is-qvl",
]) {
  test(`recipient bootstrap mock-HTTPS crypto protocol: ${scenario}`, async () => {
    const result = await exec(process.execPath, ["--experimental-test-module-mocks", "--input-type=module", "-e", HARNESS], {
      cwd: root, env: { ...process.env, RECIPIENT_BOOTSTRAP_TEST: scenario }, timeout: 20_000, maxBuffer: 1024 * 1024,
    });
    assert.match(result.stdout, new RegExp(`verified ${scenario}`));
  });
}

test("coordinator collects bootstrap roots before deferred authority and retires its phase", () => {
  const source = fs.readFileSync(new URL("./phala-production-activation-coordinator.mjs", import.meta.url), "utf8");
  const collect = source.indexOf("const recipientBootstrapEvidence = await collectPhalaRecipientBootstrapEvidence");
  const bridge = source.indexOf("const reviewedRecipientTrustProjection = await createRecipientTrustProjectionFromBootstrapEvidence", collect);
  const project = source.indexOf("await projectPhalaDeferredPublicEnvironmentAuthority", bridge);
  const retire = source.indexOf("RECIPIENT_BOOTSTRAP_AUTHORITIES.delete(recipientBootstrapAuthority)", project);
  assert.ok(collect > 0 && bridge > collect && project > bridge && retire > project);
  assert.match(source.slice(project, retire), /reviewedRecipientTrustProjection,/);
  assert.match(source, /stableRead\(reviewedSet\.deferredReviewBinding/);
  assert.match(source, /finally \{\s+if \(recipientBootstrapAuthority\)/);
});
