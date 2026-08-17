import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  FINAL_RELEASE_AUTHORITY_CORE_DOMAIN as CURRENT_DOMAIN,
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA as CURRENT_SCHEMA,
  FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN,
  FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
  FINAL_RELEASE_AUTHORITY_CORE_V3_DOMAIN,
  FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA,
  FINAL_RELEASE_AUTHORITY_CORE_V4_DOMAIN,
  FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA,
  FinalReleaseAuthorityCoreValidationError as
    CurrentFinalReleaseAuthorityCoreValidationError,
  canonicalFinalReleaseAuthorityCoreBytes as currentCanonicalV4Bytes,
  diligenceEvaluatorPolicySetRoot as currentDiligenceEvaluatorPolicySetRoot,
  finalReleaseAuthorityCoreDigest as currentV4Digest,
  historicalFinalReleaseAuthorityCoreV2Digest as currentHistoricalV2Digest,
  normalizeFinalReleaseAuthorityCore as normalizeCurrentV4,
} from "./execution-policy-release-core.mjs";
import {
  FinalReleaseAuthorityCoreValidationError,
  canonicalHistoricalFinalReleaseAuthorityCoreBytes,
  canonicalHistoricalFinalReleaseAuthorityCoreV2Bytes,
  canonicalHistoricalFinalReleaseAuthorityCoreV3Bytes,
  diligenceEvaluatorPolicySetRoot as
    historicalV3DiligenceEvaluatorPolicySetRoot,
  historicalV3CanonicalPublicHttpsOrigin,
  historicalV3EthereumKeccak256Bytes,
  historicalV3EthereumKeccak256Hex,
  historicalV3ParseCanonicalPublicHttpsUrl,
  historicalFinalReleaseAuthorityCoreDigest,
  historicalFinalReleaseAuthorityCoreV2Digest,
  historicalFinalReleaseAuthorityCoreV3Digest,
  normalizeHistoricalFinalReleaseAuthorityCore,
  normalizeHistoricalFinalReleaseAuthorityCoreV2,
  normalizeHistoricalFinalReleaseAuthorityCoreV3,
} from "./execution-policy-release-core-v3-historical.mjs";
import {
  KNOWN_DIGEST as HISTORICAL_V3_KNOWN_DIGEST,
  KNOWN_VECTOR_ID as HISTORICAL_V3_KNOWN_VECTOR_ID,
  KNOWN_VECTOR_JSON as HISTORICAL_V3_KNOWN_VECTOR_JSON,
  knownVector as historicalV3KnownVector,
} from "./execution-policy-release-core-v3-historical.fixture.mjs";
import {
  KNOWN_DIGEST as CURRENT_KNOWN_DIGEST,
  knownVector as currentKnownVector,
} from "./execution-policy-release-core.fixture.mjs";
import {
  canonicalPublicHttpsOrigin as currentCanonicalPublicHttpsOrigin,
  parseCanonicalPublicHttpsUrl as currentParseCanonicalPublicHttpsUrl,
} from "./canonical-public-https-url-core.mjs";
import {
  ethereumKeccak256Bytes as currentEthereumKeccak256Bytes,
  ethereumKeccak256Hex as currentEthereumKeccak256Hex,
} from "./ethereum-keccak.mjs";

const EXPECTED_V3_DIGEST =
  "2e2c02e0748b66690eaee79e451ab5506246ef758fb0cf08437f75ef836f48f8";
const EXPECTED_V4_DIGEST =
  "2b0d68ced175dd7dad8e1354e668f52607256fd12bb29ba78c2fe7568d0a211b";
const EXPECTED_V2_DIGEST =
  "d1bab06a461597c4b0d12d9bbf50ea37549c2023b8c37b3e8ef7638b8c874fce";

function historicalV2KnownVector() {
  const value = historicalV3KnownVector();
  value.schema = FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA;
  value.contracts.diligence_room.developer = value.operator_address;
  value.contracts.compute_credit_vault.developer_fee_bps = 500;
  value.contracts.compute_credit_vault
    .rate_policies.native.developer_fee_bps = 500;
  value.contracts.compute_credit_vault
    .rate_policies.erc20.developer_fee_bps = 500;
  delete value.requested_features.tinker_customer;
  delete value.requested_features.collaboration;
  return value;
}

test(
  "historical v3 module and intact fixture preserve the frozen KAT",
  async () => {
    const value = historicalV3KnownVector();

    assert.equal(
      HISTORICAL_V3_KNOWN_VECTOR_ID,
      "dnai.final-release-authority-core.v3/known-answer-1",
    );
    assert.equal(HISTORICAL_V3_KNOWN_DIGEST, EXPECTED_V3_DIGEST);
    assert.deepEqual(JSON.parse(HISTORICAL_V3_KNOWN_VECTOR_JSON), value);
    assert.equal(
      historicalFinalReleaseAuthorityCoreV3Digest(value),
      EXPECTED_V3_DIGEST,
    );
    assert.equal(
      historicalFinalReleaseAuthorityCoreDigest(value),
      EXPECTED_V3_DIGEST,
    );
    assert.deepEqual(
      canonicalHistoricalFinalReleaseAuthorityCoreBytes(value),
      canonicalHistoricalFinalReleaseAuthorityCoreV3Bytes(value),
    );

    const historicalModuleSource = await readFile(
      new URL(
        "./execution-policy-release-core-v3-historical.mjs",
        import.meta.url,
      ),
      "utf8",
    );
    const historicalFixtureSource = await readFile(
      new URL(
        "./execution-policy-release-core-v3-historical.fixture.mjs",
        import.meta.url,
      ),
      "utf8",
    );
    assert.doesNotMatch(
      historicalModuleSource,
      /from\s+["']\.\/execution-policy-release-core\.mjs["']/u,
    );
    assert.doesNotMatch(
      historicalFixtureSource,
      /from\s+["']\.\/execution-policy-release-core\.fixture\.mjs["']/u,
    );
    assert.doesNotMatch(
      historicalModuleSource,
      /\.\/canonical-public-https-url-core\.mjs/u,
    );
    assert.doesNotMatch(
      historicalModuleSource,
      /\.\/ethereum-keccak\.mjs/u,
    );
    assert.deepEqual(
      historicalModuleSource
        .split("\n")
        .filter((line) => line.startsWith("import ")),
      [
        "import { createHash } from \"node:crypto\";",
        "import { URL as NodeURL } from \"node:url\";",
      ],
    );

    value.release_sha = "f".repeat(40);
    assert.notEqual(historicalV3KnownVector().release_sha, value.release_sha);
  },
);

test("frozen v3 public HTTPS grammar matches its activation snapshot", () => {
  const accepted = [
    [
      "https://api.wikigen.me/compute/workload-encryption-contract",
      {},
    ],
    ["https://rpc.wikigen.me:8443/base", { allowPort: true }],
    ["https://api.wikigen.me/compute", { requirePath: true }],
  ];
  for (const [value, options] of accepted) {
    assert.deepEqual(
      historicalV3ParseCanonicalPublicHttpsUrl(value, options),
      currentParseCanonicalPublicHttpsUrl(value, options),
    );
  }
  assert.equal(
    historicalV3CanonicalPublicHttpsOrigin("https://www.wikigen.me"),
    currentCanonicalPublicHttpsOrigin("https://www.wikigen.me"),
  );

  for (const value of [
    "https://delegate.example.com",
    "https://api.wikigen.me",
    "https://a-b.c0.wikigen.me",
    "https://xn--bcher-kva.wikigen.me",
  ]) {
    const historicalCore = historicalV3KnownVector();
    historicalCore.cvm.delegate_url = value;
    const currentCore = currentKnownVector();
    currentCore.cvm.delegate_url = value;
    assert.equal(
      normalizeHistoricalFinalReleaseAuthorityCoreV3(historicalCore)
        .cvm.delegate_url,
      value,
    );
    assert.equal(
      normalizeCurrentV4(currentCore).cvm.delegate_url,
      value,
    );
  }

  for (const value of [
    "http://api.wikigen.me/path",
    "https://user@api.wikigen.me/path",
    "https://api.wikigen.me:443/path",
    "https://api.wikigen.me//path",
    "https://api.wikigen.me/../path",
    "https://api.wikigen.me/path?query=1",
    "https://api.wikigen.me/path#fragment",
    "https://127.0.0.1/path",
    "https://localhost/path",
    "https://service.home.arpa/path",
    "https://API.wikigen.me/path",
    "https://api.wikigen.me/%2f",
  ]) {
    assert.throws(
      () => historicalV3ParseCanonicalPublicHttpsUrl(value),
      /canonical public HTTPS/u,
    );
    assert.throws(
      () => currentParseCanonicalPublicHttpsUrl(value),
      /canonical public HTTPS/u,
    );
  }

  const overlongLabel = "a".repeat(64);
  const overlongHostname = Array(4).fill("a".repeat(63)).join(".");
  for (const value of [
    "http://api.wikigen.me",
    "https://user@api.wikigen.me",
    "https://api.wikigen.me:443",
    "https://api.wikigen.me:8443",
    "https://api.wikigen.me/",
    "https://api.wikigen.me/path",
    "https://api.wikigen.me//path",
    "https://api.wikigen.me/../path",
    "https://api.wikigen.me/path?query=1",
    "https://api.wikigen.me/path#fragment",
    "https://127.0.0.1",
    "https://[::1]",
    "https://foo.localhost",
    "https://foo.home.arpa",
    "https://foo.example",
    "https://API.wikigen.me",
    "https://api..wikigen.me",
    "https://-api.wikigen.me",
    "https://api-.wikigen.me",
    "https://api_.wikigen.me",
    "https://api.wikigen.me.",
    " https://api.wikigen.me",
    "https://api.wikigen.me/%2f",
    "https://bücher.wikigen.me",
    `https://${overlongLabel}.wikigen.me`,
    `https://${overlongHostname}`,
  ]) {
    const historicalCore = historicalV3KnownVector();
    historicalCore.cvm.delegate_url = value;
    const currentCore = currentKnownVector();
    currentCore.cvm.delegate_url = value;
    assert.throws(
      () => normalizeHistoricalFinalReleaseAuthorityCoreV3(historicalCore),
      /cvm\.delegate_url must be a canonical HTTPS origin/u,
    );
    assert.throws(
      () => normalizeCurrentV4(currentCore),
      /cvm\.delegate_url must be a canonical HTTPS origin/u,
    );
  }

  for (const value of [
    "https://www.wikigen.me/",
    "https://www.wikigen.me:8443",
    "https://www.wikigen.me/path",
  ]) {
    assert.throws(
      () => historicalV3CanonicalPublicHttpsOrigin(value),
      /canonical public HTTPS/u,
    );
    assert.throws(
      () => currentCanonicalPublicHttpsOrigin(value),
      /canonical public HTTPS/u,
    );
  }

  const acceptedCore = historicalV3KnownVector();
  acceptedCore.cvm.delegate_url = "https://api.wikigen.me";
  assert.equal(
    normalizeHistoricalFinalReleaseAuthorityCoreV3(acceptedCore)
      .cvm.delegate_url,
    "https://api.wikigen.me",
  );
  const rejectedCore = historicalV3KnownVector();
  rejectedCore.cvm.delegate_url = "https://api.wikigen.me/";
  assert.throws(
    () => normalizeHistoricalFinalReleaseAuthorityCoreV3(rejectedCore),
    FinalReleaseAuthorityCoreValidationError,
  );

  const broadHistoricalV2Core = historicalV2KnownVector();
  broadHistoricalV2Core.cvm.delegate_url = "https://127.0.0.1:8443";
  assert.equal(
    normalizeHistoricalFinalReleaseAuthorityCoreV2(broadHistoricalV2Core)
      .cvm.delegate_url,
    "https://127.0.0.1:8443",
  );
  const broadHistoricalV3Core = historicalV3KnownVector();
  broadHistoricalV3Core.cvm.delegate_url = "https://127.0.0.1:8443";
  assert.throws(
    () => normalizeHistoricalFinalReleaseAuthorityCoreV3(
      broadHistoricalV3Core,
    ),
    FinalReleaseAuthorityCoreValidationError,
  );

  for (const replacement of [
    "https://WWW.wikigen.me",
    "https://api.wikigen.me",
  ]) {
    const historicalCore = historicalV3KnownVector();
    historicalCore.cvm.allowed_browser_origins[0] = replacement;
    const currentCore = currentKnownVector();
    currentCore.cvm.allowed_browser_origins[0] = replacement;
    assert.throws(
      () => normalizeHistoricalFinalReleaseAuthorityCoreV3(historicalCore),
      FinalReleaseAuthorityCoreValidationError,
    );
    assert.throws(
      () => normalizeCurrentV4(currentCore),
      CurrentFinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("frozen v3 Ethereum Keccak primitive preserves KAT and rate boundaries", () => {
  const vectors = [
    {
      value: Buffer.alloc(0),
      expected:
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    },
    {
      value: Buffer.from("abc", "utf8"),
      expected:
        "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    },
    {
      value: Buffer.alloc(135, 0xa5),
      expected:
        "0xe9cd15a85e4b32b79132637b22775876cc597d8be1d19d8daf42a46d2233f0f7",
    },
    {
      value: Buffer.alloc(136, 0xa5),
      expected:
        "0x520624732be0bc2eff4ca18c833d85f5783325cb37fc3d8ec1d385aa9a6fc7f8",
    },
    {
      value: Buffer.alloc(137, 0xa5),
      expected:
        "0x171c6f03b55a0672ff99dbca84110b6bc3b8f75e1b31b5979cca100ba74f520a",
    },
  ];
  for (const { value, expected } of vectors) {
    assert.equal(historicalV3EthereumKeccak256Hex(value), expected);
    assert.equal(currentEthereumKeccak256Hex(value), expected);
    assert.deepEqual(
      historicalV3EthereumKeccak256Bytes(value),
      currentEthereumKeccak256Bytes(value),
    );
  }

  for (const value of [undefined, 7, {}]) {
    assert.throws(() => historicalV3EthereumKeccak256Hex(value), TypeError);
    assert.throws(() => currentEthereumKeccak256Hex(value), TypeError);
  }

  const commitments = historicalV3KnownVector()
    .contracts.diligence_room.evaluator_policy_commitments;
  const expectedRoot =
    "0x24d034ce2bdfb43484ddbb0c37427872c59e047fd9fab10e548f0bc5a9151230";
  assert.equal(
    historicalV3DiligenceEvaluatorPolicySetRoot(commitments),
    expectedRoot,
  );
  assert.equal(
    currentDiligenceEvaluatorPolicySetRoot(commitments),
    expectedRoot,
  );
  assert.throws(
    () => historicalV3DiligenceEvaluatorPolicySetRoot([
      commitments[0],
      commitments[0],
      commitments[2],
    ]),
    FinalReleaseAuthorityCoreValidationError,
  );
});

test("historical v2 remains frozen beside historical v3", () => {
  const value = historicalV2KnownVector();

  assert.equal(
    historicalFinalReleaseAuthorityCoreV2Digest(value),
    EXPECTED_V2_DIGEST,
  );
  assert.equal(
    historicalFinalReleaseAuthorityCoreDigest(value),
    EXPECTED_V2_DIGEST,
  );
  assert.equal(currentHistoricalV2Digest(value), EXPECTED_V2_DIGEST);
  assert.deepEqual(
    canonicalHistoricalFinalReleaseAuthorityCoreBytes(value),
    canonicalHistoricalFinalReleaseAuthorityCoreV2Bytes(value),
  );
  assert.deepEqual(
    normalizeHistoricalFinalReleaseAuthorityCore(value),
    normalizeHistoricalFinalReleaseAuthorityCoreV2(value),
  );
});

test("historical replay dispatches only by exact v2 or v3 schema", () => {
  const v2 = historicalV2KnownVector();
  const v3 = historicalV3KnownVector();

  assert.deepEqual(
    normalizeHistoricalFinalReleaseAuthorityCore(v2),
    normalizeHistoricalFinalReleaseAuthorityCoreV2(v2),
  );
  assert.deepEqual(
    normalizeHistoricalFinalReleaseAuthorityCore(v3),
    normalizeHistoricalFinalReleaseAuthorityCoreV3(v3),
  );

  for (const value of [
    null,
    [],
    {},
    { ...v3, schema: "dnai.final-release-authority-core.v4" },
    { ...v3, schema: `${FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA} ` },
  ]) {
    assert.throws(
      () => normalizeHistoricalFinalReleaseAuthorityCore(value),
      FinalReleaseAuthorityCoreValidationError,
    );
  }

  const v2BodyClaimingV3 = historicalV2KnownVector();
  v2BodyClaimingV3.schema = FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA;
  assert.throws(
    () => normalizeHistoricalFinalReleaseAuthorityCore(v2BodyClaimingV3),
    FinalReleaseAuthorityCoreValidationError,
  );

  const v3BodyClaimingV2 = historicalV3KnownVector();
  v3BodyClaimingV2.schema = FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA;
  assert.throws(
    () => normalizeHistoricalFinalReleaseAuthorityCore(v3BodyClaimingV2),
    FinalReleaseAuthorityCoreValidationError,
  );

  const dispatcherSource =
    normalizeHistoricalFinalReleaseAuthorityCore.toString();
  assert.doesNotMatch(dispatcherSource, /\btry\b|\bcatch\b/u);
  assert.match(dispatcherSource, /FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA/u);
  assert.match(dispatcherSource, /FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA/u);
});

test("current unqualified exports advance to v4 while frozen v3 remains replay-only", () => {
  const current = currentKnownVector();
  const historical = historicalV3KnownVector();

  assert.equal(CURRENT_SCHEMA, FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA);
  assert.equal(CURRENT_DOMAIN, FINAL_RELEASE_AUTHORITY_CORE_V4_DOMAIN);
  assert.notEqual(CURRENT_SCHEMA, FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA);
  assert.notEqual(CURRENT_DOMAIN, FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN);
  assert.notEqual(CURRENT_SCHEMA, FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA);
  assert.notEqual(CURRENT_DOMAIN, FINAL_RELEASE_AUTHORITY_CORE_V3_DOMAIN);
  assert.equal(CURRENT_KNOWN_DIGEST, EXPECTED_V4_DIGEST);
  assert.equal(currentV4Digest(current), EXPECTED_V4_DIGEST);
  assert.equal(normalizeCurrentV4(current).schema, CURRENT_SCHEMA);
  assert.notDeepEqual(
    currentCanonicalV4Bytes(current),
    canonicalHistoricalFinalReleaseAuthorityCoreV3Bytes(historical),
  );
  assert.throws(
    () => normalizeCurrentV4(historical),
    CurrentFinalReleaseAuthorityCoreValidationError,
  );
  assert.deepEqual(
    normalizeHistoricalFinalReleaseAuthorityCoreV3(historical),
    normalizeHistoricalFinalReleaseAuthorityCore(historical),
  );
  assert.throws(
    () => normalizeHistoricalFinalReleaseAuthorityCore(current),
    FinalReleaseAuthorityCoreValidationError,
  );
});
