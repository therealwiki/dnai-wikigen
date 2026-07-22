import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARATION_RECEIPT_SCHEMA,
  PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARE_REQUEST_SCHEMA,
  main,
  preparePhalaProductionAuthorityWorkspace,
} from "./phala-production-authority-workspace-prepare.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  listPhalaPinnedPrivateEntries,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";
import {
  canonicalResidentJsonText,
} from "./phala-production-resident-io.mjs";

const CLI_PATH = fileURLToPath(new URL(
  "./phala-production-authority-workspace-prepare.mjs",
  import.meta.url,
));

function fixture(t) {
  const root = fs.realpathSync.native(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-authority-workspace-"),
  ));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return {
    root,
    request: {
      schema: PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARE_REQUEST_SCHEMA,
      authorities: {
        evidenceExchangePath: path.join(root, "evidence"),
        outputPath: path.join(root, "outputs"),
        postlaunchAuthorityExchangePath: path.join(root, "postlaunch-authority"),
        signingExchangePath: path.join(root, "signing"),
      },
    },
  };
}

test("workspace preparation emits four strict empty authorities and no activation claim", (t) => {
  const { request } = fixture(t);
  const receipt = preparePhalaProductionAuthorityWorkspace(request);
  assert.equal(
    receipt.schema,
    PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARATION_RECEIPT_SCHEMA,
  );
  assert.equal(receipt.activation_mutation_authorized, false);
  assert.equal(receipt.live_traffic_authorized, false);
  assert.equal(receipt.externally_reviewed_and_sealed_into_activation_request, false);
  assert.deepEqual(
    Object.keys(receipt.resident_activation_authorities),
    [
      "evidenceExchangeAuthority",
      "outputAuthority",
      "postlaunchAuthorityExchangeAuthority",
      "signingExchangeAuthority",
    ],
  );

  for (const authority of Object.values(receipt.resident_activation_authorities)) {
    const handle = pinPhalaPrivateDirectory(authority.path, {
      expectedIdentityAnchorSha256: authority.identity_anchor_sha256,
    });
    try {
      assert.deepEqual(listPhalaPinnedPrivateEntries(handle), []);
    } finally {
      closePhalaPinnedPrivateDirectory(handle);
    }
  }
});

test("all four authority roots are pairwise distinct and non-nesting", (t) => {
  const { root, request } = fixture(t);
  const equal = structuredClone(request);
  equal.authorities.postlaunchAuthorityExchangePath =
    equal.authorities.evidenceExchangePath;
  assert.throws(
    () => preparePhalaProductionAuthorityWorkspace(equal),
    /pairwise distinct/,
  );

  const nested = structuredClone(request);
  nested.authorities.postlaunchAuthorityExchangePath = path.join(
    nested.authorities.evidenceExchangePath,
    "postlaunch",
  );
  assert.throws(
    () => preparePhalaProductionAuthorityWorkspace(nested),
    /must not contain one another/,
  );

  assert.equal(fs.existsSync(path.join(root, "evidence")), false);
});

test("workspace preparation is idempotent only through the exact observed anchors", (t) => {
  const { request } = fixture(t);
  const first = preparePhalaProductionAuthorityWorkspace(request);
  const second = preparePhalaProductionAuthorityWorkspace(request);
  assert.deepEqual(second, first);
});

test("a prepared receipt cannot attach a renamed and substituted authority", (t) => {
  const { root, request } = fixture(t);
  const receipt = preparePhalaProductionAuthorityWorkspace(request);
  const authority = receipt.resident_activation_authorities
    .evidenceExchangeAuthority;
  fs.renameSync(authority.path, path.join(root, "held-evidence"));
  fs.mkdirSync(authority.path, { mode: 0o700 });
  assert.throws(
    () => pinPhalaPrivateDirectory(authority.path, {
      expectedIdentityAnchorSha256: authority.identity_anchor_sha256,
    }),
    /identity changed|automatic rebind|differs from external authenticated authority/,
  );
});

test("workspace preparation refuses nonempty persistence contents", (t) => {
  const { request } = fixture(t);
  fs.mkdirSync(request.authorities.evidenceExchangePath, { mode: 0o700 });
  fs.writeFileSync(
    path.join(request.authorities.evidenceExchangePath, "squatted.json"),
    "{}\n",
    { mode: 0o600 },
  );
  assert.throws(
    () => preparePhalaProductionAuthorityWorkspace(request),
    /lack an authenticated directory identity anchor|must be empty/,
  );
});

test("workspace preparation CLI requires canonical owned mode-0600 input", async (t) => {
  const { root, request } = fixture(t);
  const requestPath = path.join(root, "prepare-request.json");
  fs.writeFileSync(requestPath, canonicalResidentJsonText(request), { mode: 0o644 });
  fs.chmodSync(requestPath, 0o644);
  await assert.rejects(
    () => main(["--prepare-request", requestPath]),
    /exact-mode-0600/,
  );
  const result = spawnSync(process.execPath, [
    CLI_PATH,
    "--prepare-request",
    requestPath,
  ], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "authority_workspace_preparation_failed\n");
  assert.doesNotMatch(result.stderr, new RegExp(root.replaceAll("/", "\\/")));
});
