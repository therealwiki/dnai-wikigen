import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  RELEASE_AUTHORITY_SIGNATURE_SCHEME,
  ceremonyAuthorizationReviewSigningPayload,
  releaseAuthorityReviewSigningMessage,
  releaseAuthorityReviewSigningPayloadSha256,
} from "./release-ceremony-authorization.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_BASENAME,
  PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA,
  PHALA_PRODUCTION_STAGE_B_EXTERNAL_SIGNATURES_SCHEMA,
  attachPhalaProductionStageB,
  parsePhalaProductionStageBAttachmentArgs,
} from "./phala-production-stage-b-attach.mjs";
import {
  canonicalResidentJsonText,
} from "./phala-production-resident-io.mjs";
import {
  syntheticReleaseAuthorityStagesFixture,
} from "./release-authority-stages.fixture.mjs";

function privateRoot(t) {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-stage-b-attach-")),
  );
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function publicIdentity(identity, basename) {
  return Object.freeze({
    basename,
    sha256: identity.sha256,
    size: identity.size,
    mode: identity.mode,
  });
}

async function signingExchange(t, { forgeSignature = false } = {}) {
  const root = privateRoot(t);
  const exchange = path.join(root, forgeSignature ? "forged" : "valid");
  const handle = pinPhalaPrivateDirectory(exchange);
  const fixture = await syntheticReleaseAuthorityStagesFixture();
  const body = structuredClone(fixture.stageOne);
  delete body.review;
  const prior = fixture.stageOne.review;
  const signedAtMs = Math.floor(Date.now() / 1_000) * 1_000;
  const payload = ceremonyAuthorizationReviewSigningPayload(body, {
    reviewer_authority_genesis_sha256:
      prior.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      prior.reviewer_authority_genesis_acceptance_sha256,
    approved_reviewer_hashes: prior.approved_reviewer_hashes,
    reviewer_root_hash: prior.reviewer_root_hash,
    reviewer_set_sha256: prior.reviewer_set_sha256,
    signed_at: new Date(signedAtMs).toISOString(),
    expires_at: new Date(signedAtMs + 9 * 60 * 1_000).toISOString(),
  });
  const prefix = `stage-b-${fixture.stageOne.release_sha}-testfixture000000000000`;
  const bodyBasename = `${prefix}.unsigned-body.json`;
  const payloadBasename = `${prefix}.signing-payload.json`;
  const signaturesBasename = `${prefix}.external-signatures.json`;
  const outputBasename = `${prefix}.signed.json`;
  const bodyIdentity = createExclusivePhalaPinnedPrivateFile(
    handle,
    bodyBasename,
    Buffer.from(canonicalResidentJsonText(body), "utf8"),
  );
  const payloadIdentity = createExclusivePhalaPinnedPrivateFile(
    handle,
    payloadBasename,
    Buffer.from(canonicalResidentJsonText(payload), "utf8"),
  );
  const anchor = phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle);
  const manifest = {
    schema: PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA,
    status: "waiting_for_external_two_reviewer_signatures",
    truth_status:
      "non_signing_candidate_attachment_only_same_process_coordinator_validation_still_required",
    release_sha: fixture.stageOne.release_sha,
    batch_id: "stage-b-helper-test-batch",
    signing_payload_sha256:
      releaseAuthorityReviewSigningPayloadSha256(payload),
    signing_message: releaseAuthorityReviewSigningMessage(payload),
    signing_exchange_directory_identity_anchor_sha256: anchor,
    unsigned_body_file: publicIdentity(bodyIdentity, bodyBasename),
    signing_payload_file: publicIdentity(payloadIdentity, payloadBasename),
    external_signatures_input: {
      basename: signaturesBasename,
      mode: "0600",
      canonical_json_required: true,
    },
    signed_b_output: {
      basename: outputBasename,
      mode: "0600",
      canonical_json_required: true,
    },
    automatic_retry_authorized: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  };
  createExclusivePhalaPinnedPrivateFile(
    handle,
    PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_BASENAME,
    Buffer.from(canonicalResidentJsonText(manifest), "utf8"),
  );
  const byAddress = new Map(
    fixture.accounts.map((account) => [account.address.toLowerCase(), account]),
  );
  const signatures = [];
  for (let index = 0; index < fixture.reviewers.length; index += 1) {
    const reviewer = fixture.reviewers[index];
    const account = forgeSignature && index === 0
      ? privateKeyToAccount(`0x${"33".repeat(32)}`)
      : byAddress.get(reviewer.address);
    signatures.push({
      ...reviewer,
      signature: (await account.signMessage({
        message: releaseAuthorityReviewSigningMessage(payload),
      })).toLowerCase(),
    });
  }
  createExclusivePhalaPinnedPrivateFile(
    handle,
    signaturesBasename,
    Buffer.from(canonicalResidentJsonText({
      schema: PHALA_PRODUCTION_STAGE_B_EXTERNAL_SIGNATURES_SCHEMA,
      purpose: "stage_b_ceremony_authorization_review",
      signature_scheme: RELEASE_AUTHORITY_SIGNATURE_SCHEME,
      signing_payload_sha256:
        releaseAuthorityReviewSigningPayloadSha256(payload),
      signatures,
    }), "utf8"),
  );
  closePhalaPinnedPrivateDirectory(handle);
  return { anchor, exchange, outputBasename, payload, body };
}

test("non-signing helper attaches exact external signatures to code-owned signed B", async (t) => {
  const value = await signingExchange(t);
  const receipt = attachPhalaProductionStageB({
    exchange: value.exchange,
    expectedAnchorSha256: value.anchor,
  });
  assert.equal(receipt.signature_count, 2);
  assert.equal(receipt.signer_key_material_accepted, false);
  assert.equal(receipt.activation_mutation_authorized, false);
  assert.equal(receipt.live_traffic_authorized, false);
  const handle = pinPhalaPrivateDirectory(value.exchange, {
    expectedIdentityAnchorSha256: value.anchor,
  });
  try {
    const signed = JSON.parse(readPhalaPinnedPrivateFile(
      handle,
      value.outputBasename,
      { mode: 0o600, minimum: 2 },
    ).toString("utf8"));
    assert.deepEqual(
      Object.fromEntries(Object.entries(signed).filter(([key]) => key !== "review")),
      value.body,
    );
    assert.equal(
      signed.review.signing_payload_sha256,
      releaseAuthorityReviewSigningPayloadSha256(value.payload),
    );
    assert.equal(signed.review.signatures.length, 2);
  } finally {
    closePhalaPinnedPrivateDirectory(handle);
  }
});

test("forged signatures fail before any signed-B candidate is created", async (t) => {
  const value = await signingExchange(t, { forgeSignature: true });
  assert.throws(
    () => attachPhalaProductionStageB({
      exchange: value.exchange,
      expectedAnchorSha256: value.anchor,
    }),
    /signature verification failed/,
  );
  assert.equal(fs.existsSync(path.join(value.exchange, value.outputBasename)), false);
});

test("helper rejects signer, key, RPC, and unpinned exchange argument surfaces", () => {
  for (const argv of [
    ["--private-key", "0xdead", "--exchange", "/tmp/x"],
    ["--exchange", "/tmp/x", "--rpc-url", "https://example.test"],
    ["--exchange", "/tmp/x", "--account", "dev"],
    ["--exchange", "/tmp/x", "--expected-anchor-sha256", "sha256:bad"],
  ]) {
    assert.throws(
      () => parsePhalaProductionStageBAttachmentArgs(argv),
      /unsupported|requires exactly|canonical SHA-256/,
    );
  }
});

test("attachment is create-new and cannot replay over an existing candidate", async (t) => {
  const value = await signingExchange(t);
  attachPhalaProductionStageB({
    exchange: value.exchange,
    expectedAnchorSha256: value.anchor,
  });
  assert.throws(
    () => attachPhalaProductionStageB({
      exchange: value.exchange,
      expectedAnchorSha256: value.anchor,
    }),
    /already exists|File exists|create/i,
  );
});
