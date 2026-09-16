import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import * as historicalAuthority from
  "./phala-seven-cvm-historical-release-verification-authority.mjs";

test("historical authority has no runtime seam and rejects unbranded values", () => {
  assert.equal(historicalAuthority.__test, undefined);
  const synthetic =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  const productionShaped = structuredClone(synthetic);
  productionShaped.evidence_mode = "production";
  for (const candidate of [synthetic, productionShaped, structuredClone(synthetic)]) {
    assert.throws(
      () => historicalAuthority
        .assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(
          candidate,
        ),
      /not historically reconstructed/,
    );
    assert.throws(
      () => historicalAuthority
        .historicallyReconstructedPhalaSevenCvmReleaseVerificationAuthorityMetadata(
          candidate,
        ),
      /not historically reconstructed/,
    );
  }
});

test("historical ceremony nonce is bound to authenticated R, not signed-A authorization ID", () => {
  const fixture =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  const distinctAuthorizationId = `sha256:${"f1".repeat(32)}`;
  assert.notEqual(
    fixture.ceremony_nonce,
    `0x${distinctAuthorizationId.slice("sha256:".length)}`,
  );
  const source = readFileSync(
    new URL(
      "./phala-seven-cvm-historical-release-verification-authority.mjs",
      import.meta.url,
    ),
    "utf8",
  );
  assert.doesNotMatch(source, /signedA\.authorization_id/);
  assert.match(
    source,
    /authority\.ceremony_nonce,[\s\S]*?plan\.runtime_commitments\.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE/,
  );
});

test("ordinary Node cannot spoof a historical production-authority mint", () => {
  const moduleUrl = new URL(
    "./phala-seven-cvm-historical-release-verification-authority.mjs",
    import.meta.url,
  );
  const fixtureUrl = new URL(
    "./phala-seven-cvm-release-verification-authority.fixture.mjs",
    import.meta.url,
  );
  const spoofedEntrypoint = new URL(
    "./phala-seven-cvm-historical-release-verification-authority.test.mjs",
    import.meta.url,
  );
  const child = spawnSync(process.execPath, [
    "--input-type=module",
    "--eval",
    [
      `process.env.NODE_TEST_CONTEXT = "child-v8";`,
      `process.argv[1] = ${JSON.stringify(spoofedEntrypoint.pathname)};`,
      `const authorityModule = await import(${JSON.stringify(moduleUrl.href)});`,
      `const fixtureModule = await import(${JSON.stringify(fixtureUrl.href)});`,
      `if (authorityModule.__test !== undefined) process.exit(91);`,
      `const synthetic = structuredClone(fixtureModule.syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture());`,
      `synthetic.evidence_mode = "production";`,
      `try {`,
      `  authorityModule.assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(synthetic);`,
      `  process.exit(92);`,
      `} catch { process.stdout.write("rejected"); }`,
    ].join("\n"),
    spoofedEntrypoint.pathname,
  ], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, NODE_TEST_CONTEXT: "child-v8" },
    encoding: "utf8",
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "rejected");
});
