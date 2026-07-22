import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_TRUTH,
  __test,
  assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority,
  historicallyReconstructedPhalaSevenCvmReleaseVerificationAuthorityMetadata,
} from "./phala-seven-cvm-historical-release-verification-authority.mjs";
import {
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";

const sha = (byte) => `sha256:${byte.repeat(64)}`;

function metadata(authority) {
  return {
    schema: PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_TRUTH,
    release_verification_authority_sha256:
      phalaSevenCvmReleaseVerificationAuthoritySha256(authority),
    nonlive_bootstrap_authorization_receipt_sha256: sha("1"),
    executor_final_state_sha256: sha("2"),
    seven_cvm_launch_completion_receipt_sha256: sha("3"),
    seven_cvm_verified_evidence_set_sha256: sha("4"),
    historical_transcript_file_set_sha256: sha("5"),
    cvm_descriptor_runtime_authority_sha256:
      authority.cvm_descriptor_runtime_authority_sha256,
    pre_ceremony_runtime_authority_sha256: sha("6"),
    ceremony_authorization_sha256: sha("7"),
  };
}

test("historical authority uses a distinct restart-only brand and captures exact source digests", async () => {
  const releaseAuthority =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  assert.throws(
    () => assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(
      releaseAuthority,
    ),
    /not historically reconstructed/,
  );
  const historical =
    __test.createSyntheticHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority({
      authority: releaseAuthority,
      metadata: metadata(releaseAuthority),
    });
  assert.notEqual(historical, releaseAuthority);
  assert.equal(
    assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(historical),
    historical,
  );
  assert.deepEqual(
    historicallyReconstructedPhalaSevenCvmReleaseVerificationAuthorityMetadata(historical),
    metadata(releaseAuthority),
  );
  assert.throws(
    () => assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(
      releaseAuthority,
    ),
    /not historically reconstructed/,
  );
  assert.throws(
    () => assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(
      structuredClone(historical),
    ),
    /not historically reconstructed/,
  );

  const child = spawnSync(process.execPath, [
    "--input-type=module",
    "--eval",
    [
      "import fs from 'node:fs';",
      "import { assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority as check } from './scripts/phala-seven-cvm-historical-release-verification-authority.mjs';",
      "const value = JSON.parse(fs.readFileSync(0, 'utf8'));",
      "try { check(value); process.exit(9); } catch { process.stdout.write('rejected'); }",
    ].join("\n"),
  ], {
    cwd: new URL("..", import.meta.url),
    input: JSON.stringify(historical),
    encoding: "utf8",
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "rejected");
});

test("historical synthetic metadata is exact and authority-digest bound", async () => {
  const releaseAuthority =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  const wrong = metadata(releaseAuthority);
  wrong.release_verification_authority_sha256 = sha("8");
  assert.throws(
    () => __test
      .createSyntheticHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority({
        authority: releaseAuthority,
        metadata: wrong,
      }),
    /metadata digest drifted/,
  );
  const extra = { ...metadata(releaseAuthority), extra: sha("9") };
  assert.throws(
    () => __test
      .createSyntheticHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority({
        authority: releaseAuthority,
        metadata: extra,
      }),
    /exactly the frozen fields/,
  );
});
