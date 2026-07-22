import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
  independentTdxVerdictSigningDigest as productionIndependentVerdictDigest,
  normalizePhalaComputeWorkloadRecipientActivationVerification as productionNormalizeActivation,
  normalizePhalaComputeWorkloadRecipientSourceActivation as productionNormalizeSource,
  phalaComputeWorkloadRecipientActivationVerificationSha256 as productionActivationDigest,
  phalaComputeWorkloadRecipientSourceActivationSha256 as productionSourceDigest,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY,
  PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS,
  independentTdxVerdictSigningDigest,
  normalizePhalaComputeWorkloadRecipientActivationVerification,
  normalizePhalaComputeWorkloadRecipientSourceActivation,
  parsePhalaHistoricalTdxV4QuoteCandidates,
  phalaComputeWorkloadRecipientActivationVerificationSha256,
  phalaComputeWorkloadRecipientSourceActivationSha256,
  qvlChallengeSigningDigest,
  reconstructPhalaSevenCvmHistoricalEvidenceSet,
  recoverIndependentEip191PersonalSignerFromRawDigest,
  verifyPhalaHistoricalRawDigestSignature,
} from "./phala-seven-cvm-historical-evidence-core.mjs";
import {
  recoverIndependentEip191PersonalSigner,
} from "../web/scripts/independent-eip191-replay-core.mjs";
import {
  syntheticPhalaSevenCvmVerifierEvidenceFixture,
} from "./phala-seven-cvm-verifier-evidence.fixture.mjs";

let fixturePromise;
function fixture() {
  fixturePromise ||= syntheticPhalaSevenCvmVerifierEvidenceFixture();
  return fixturePromise;
}

function canonicalFixtureValue(value) {
  if (Array.isArray(value)) return value.map(canonicalFixtureValue);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [
    key,
    canonicalFixtureValue(value[key]),
  ]));
}

function historicalRawFile(value) {
  const text = `${JSON.stringify(canonicalFixtureValue(value), null, 2)}\n`;
  return {
    value: structuredClone(value),
    sha256: `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`,
    size: Buffer.byteLength(text, "utf8"),
  };
}

function raw14FromFixture(value) {
  const raw14 = {};
  for (const input of value.qvlRawInputs) {
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS[input.domain];
    raw14[flags.first] = historicalRawFile(input.request);
    raw14[flags.second] = historicalRawFile(input.response);
  }
  for (const input of value.workloadRawInputs) {
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS[input.challenge.domain];
    raw14[flags.first] = historicalRawFile(input.challenge);
    raw14[flags.second] = historicalRawFile(input.verdict);
  }
  return raw14;
}

test("pure historical O structures and digests retain production byte parity", async () => {
  const value = await fixture();
  assert.equal(
    independentTdxVerdictSigningDigest(
      value.computeWorkloadActivationRaw.authenticated_verdict,
    ),
    productionIndependentVerdictDigest(
      value.computeWorkloadActivationRaw.authenticated_verdict,
    ),
  );
  assert.deepEqual(
    normalizePhalaComputeWorkloadRecipientSourceActivation(
      value.computeWorkloadActivationRaw,
    ),
    productionNormalizeSource(value.computeWorkloadActivationRaw),
  );
  assert.equal(
    phalaComputeWorkloadRecipientSourceActivationSha256(
      value.computeWorkloadActivationRaw,
    ),
    productionSourceDigest(value.computeWorkloadActivationRaw),
  );
  assert.deepEqual(
    normalizePhalaComputeWorkloadRecipientActivationVerification(
      value.computeWorkloadActivationEvidence,
    ),
    productionNormalizeActivation(value.computeWorkloadActivationEvidence),
  );
  assert.equal(
    phalaComputeWorkloadRecipientActivationVerificationSha256(
      value.computeWorkloadActivationEvidence,
    ),
    productionActivationDigest(value.computeWorkloadActivationEvidence),
  );
});

test("TDX v4 structural parser extracts TD10 and TD15 candidates without verifying DCAP", () => {
  const quote = Buffer.alloc(1_024);
  quote.writeUInt16LE(4, 0);
  quote.writeUInt32LE(0x81, 4);
  for (let index = 48; index < 696; index += 1) quote[index] = index & 0xff;
  const parsed = parsePhalaHistoricalTdxV4QuoteCandidates(quote);
  assert.equal(parsed.report_data, `0x${quote.subarray(568, 632).toString("hex")}`);
  assert.deepEqual(parsed.candidates.map(({ body_type: type }) => type), ["td10", "td15"]);
  assert.equal(parsed.candidates[0].measurements.mr_td,
    quote.subarray(184, 232).toString("hex"));
  assert.equal(parsed.candidates[1].measurements.mr_service_td,
    quote.subarray(648, 696).toString("hex"));
  assert.throws(() => parsePhalaHistoricalTdxV4QuoteCandidates(Buffer.alloc(1_024)));
});

test("historical authority bytes exactly match the production receipt authority", () => {
  assert.deepEqual(
    PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY,
    PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
  );
});

test("workload signatures replay over raw bytes32, not the digest's UTF-8 hex", async () => {
  const value = await fixture();
  const challenge = value.workloadRawInputs[0].challenge;
  const digest = qvlChallengeSigningDigest(challenge);
  const expectedAddress = challenge.verifier_address;

  assert.equal(
    recoverIndependentEip191PersonalSignerFromRawDigest({
      digest,
      signature: challenge.verifier_signature,
    }),
    expectedAddress,
  );
  assert.notEqual(
    recoverIndependentEip191PersonalSigner({
      message: digest,
      signature: challenge.verifier_signature,
    }),
    expectedAddress,
  );
  const replay = verifyPhalaHistoricalRawDigestSignature({
    digest,
    signature: challenge.verifier_signature,
    expectedAddress,
  });
  assert.equal(replay.verified, true);
  assert.equal(replay.message_mode, "eip191_personal_sign_raw_bytes32");
  assert.equal(replay.current_operation_authorized, false);

  const tamperedDigest = `${digest.slice(0, -1)}${digest.endsWith("1") ? "2" : "1"}`;
  assert.throws(() => verifyPhalaHistoricalRawDigestSignature({
    digest: tamperedDigest,
    signature: challenge.verifier_signature,
    expectedAddress,
  }), /does not match verifier address/);
});

test("historical signer injection is synchronous and rejects thenables", async () => {
  const value = await fixture();
  const challenge = value.workloadRawInputs[0].challenge;
  const digest = qvlChallengeSigningDigest(challenge);
  assert.throws(() => verifyPhalaHistoricalRawDigestSignature({
    digest,
    signature: challenge.verifier_signature,
    expectedAddress: challenge.verifier_address,
    recoverPersonalSigner: () => Promise.resolve(challenge.verifier_address),
  }), /must be synchronous and static/);
  assert.equal(verifyPhalaHistoricalRawDigestSignature({
    digest,
    signature: challenge.verifier_signature,
    expectedAddress: challenge.verifier_address,
    recoverPersonalSigner: () => challenge.verifier_address,
  }).verified, true);
});

test("full reconstruction rejects opaque synthetic quote bodies before context use", async () => {
  const value = await fixture();
  assert.throws(() => reconstructPhalaSevenCvmHistoricalEvidenceSet({
    rawArtifacts: raw14FromFixture(value),
    historicalEvidenceContext: null,
  }), /quote-v4|TDX v4/i);
});

test("historical evidence core has a Cloudflare-safe static closure", () => {
  const source = readFileSync(
    new URL("./phala-seven-cvm-historical-evidence-core.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "node:fs", "node:path", "node:child_process", "node:os", "Date.now(",
    "WeakMap", "WeakSet", "import(", "process.", "fetch(",
    "phala-seven-cvm-verifier-evidence.mjs",
  ]) {
    assert.equal(source.includes(forbidden), false, `reachable source contains ${forbidden}`);
  }
  assert.match(source, /raw_quote_present_in_private_input_files: true/);
  assert.match(source, /raw_quote_not_embedded_in_derived_evidence_objects: true/);
  assert.equal(source.includes("rawQuotePersisted"), false);
  assert.match(source, /dcap_reverified: false/);
  assert.match(source, /intel_collateral_revalidated: false/);
  assert.match(source, /freshness_renewed: false/);
  assert.match(source, /live_traffic_authorized: false/);
});

test("normalizers reject accessor-bearing historical activation graphs before use", async () => {
  const value = await fixture();
  const source = structuredClone(value.computeWorkloadActivationRaw);
  Object.defineProperty(source, "schema", {
    enumerable: true,
    get() {
      throw new Error("accessor executed");
    },
  });
  assert.throws(
    () => normalizePhalaComputeWorkloadRecipientSourceActivation(source),
    /canonical|accessor|plain/i,
  );
});
