import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PHALA_REVIEWED_CAPSULE_EXPORTS,
  PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY,
  PHALA_SDK_ACTION_REQUEST_POLICY_SHA256,
  PHALA_SDK_REGISTRY_AUDIT_INPUT_MANIFEST_SHA256,
  PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SHA256,
  PHALA_SDK_RUNTIME_CAPSULE_SHA256,
  PHALA_SDK_UPSTREAM_REGISTRY_EVIDENCE_SHA256,
  assertReviewedCapsuleSourceCapabilityBoundary,
  verifyReviewedPhalaSdkRuntimeCapsuleMaterial,
} from "./phala-sdk-runtime-capsule.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => fs.readFileSync(path.join(ROOT, relative));
const sha256 = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const canonical = (value) => {
  const sorted = (item) => Array.isArray(item) ? item.map(sorted)
    : item && typeof item === "object"
      ? Object.fromEntries(Object.keys(item).sort().map((key) => [key, sorted(item[key])]))
      : item;
  return Buffer.from(`${JSON.stringify(sorted(value), null, 2)}\n`);
};

function material() {
  return {
    authorityBytes: read("deployments/phala-sdk-runtime-capsule-authority.json"),
    registryEvidenceBytes: read("deployments/phala-sdk-upstream-registry-evidence.json"),
    capsuleBytes: read("scripts/vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs"),
    legalNoticeBytes: read("scripts/vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs.LEGAL.txt"),
    cloudTarballBytes: read("scripts/vendor/npm/phala-cloud-0.4.0.tgz"),
    dstackTarballBytes: read("scripts/vendor/npm/phala-dstack-sdk-0.5.8.tgz"),
  };
}

test("portable capsule material verification pins SDK 0.4.0, dstack 0.5.8, and the exact 18-action policy", () => {
  const bytes = material();
  const verified = verifyReviewedPhalaSdkRuntimeCapsuleMaterial(bytes);
  const authority = JSON.parse(bytes.authorityBytes);
  assert.equal(verified.authority_sha256, PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SHA256);
  assert.equal(verified.capsule_sha256, PHALA_SDK_RUNTIME_CAPSULE_SHA256);
  assert.equal(verified.request_policy_sha256, PHALA_SDK_ACTION_REQUEST_POLICY_SHA256);
  assert.equal(verified.phala_cloud.package_version, "0.4.0");
  assert.equal(verified.dstack_sdk.package_version, "0.5.8");
  assert.equal(authority.request_policy.action_count, 18);
  assert.equal(PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY.phala_cloud_version, "0.4.0");
  assert.deepEqual(Object.keys(bytes).sort(), ["authorityBytes", "capsuleBytes", "cloudTarballBytes", "dstackTarballBytes", "legalNoticeBytes", "registryEvidenceBytes"],
    "historical audit inputs are not added to the executable material API");
});

for (const field of Object.keys(material())) {
  test(`capsule verification rejects changed ${field}`, () => {
    const bytes = material();
    bytes[field] = Buffer.from(bytes[field]);
    bytes[field][Math.floor(bytes[field].length / 2)] ^= 1;
    assert.throws(() => verifyReviewedPhalaSdkRuntimeCapsuleMaterial(bytes), /digest|reviewed (?:static )?pin|source package/u);
  });
}

test("verified capsule has exactly the 22 callable exports and no ambient network or loader capability", async () => {
  const bytes = material();
  verifyReviewedPhalaSdkRuntimeCapsuleMaterial(bytes);
  assertReviewedCapsuleSourceCapabilityBoundary(bytes.capsuleBytes);
  const imported = await import(`data:text/javascript;base64,${bytes.capsuleBytes.toString("base64")}`);
  assert.deepEqual(Object.keys(imported).sort(), [...PHALA_REVIEWED_CAPSULE_EXPORTS]);
  assert.equal(Object.keys(imported).length, 22);
  assert.equal(Object.values(imported).every((value) => typeof value === "function"), true);
  assert.throws(() => PHALA_REVIEWED_CAPSULE_EXPORTS.push("createClient"), TypeError);
});

test("export-table removal cannot retain the reviewed capsule identity", () => {
  const bytes = material();
  const source = bytes.capsuleBytes.toString("utf8");
  const exportStart = source.lastIndexOf("export {");
  assert.ok(exportStart > 0);
  const changed = source.slice(0, exportStart) + source.slice(exportStart).replace("  getWorkspace,\n", "");
  assert.notEqual(changed, source);
  assert.throws(() => verifyReviewedPhalaSdkRuntimeCapsuleMaterial({ ...bytes, capsuleBytes: Buffer.from(changed) }), /reviewed static pin/u);
});

test("direct capability injection remains forbidden independently of digest checking", () => {
  const imports = 'import {} from "crypto";\nimport {} from "node:crypto";\n';
  for (const source of [
    'fetch("https://example.invalid")', 'globalThis["fetch"]("https://example.invalid")',
    'import("node:fs")', 'require("node:https")', 'process.env.HOME',
    'Function("return 1")', 'eval("1")', 'WebAssembly.compile(new Uint8Array())',
    'import fs from "node:fs";', 'import net from "node:net";', 'const addon = "bad.node";',
  ]) {
    assert.throws(() => assertReviewedCapsuleSourceCapabilityBoundary(Buffer.from(imports + source)),
      /forbidden direct capability|unreviewed runtime module/u);
  }
});

test("registry evidence retains actual fresh-TUF verification rather than a registry-only claim", () => {
  const bytes = material();
  const registry = JSON.parse(bytes.registryEvidenceBytes);
  assert.equal(sha256(bytes.registryEvidenceBytes), PHALA_SDK_UPSTREAM_REGISTRY_EVIDENCE_SHA256);
  assert.deepEqual(registry.verification.external_network_hosts, ["registry.npmjs.org", "tuf-repo-cdn.sigstore.dev"]);
  assert.equal(registry.verification.attestation_verifier, "pacote_verifyAttestations_with_fresh_sigstore_TUF_update_and_force_cache");
  assert.equal(registry.verification.ambient_registry_tokens_used, false);
  const falseClaim = structuredClone(registry);
  falseClaim.verification.external_network_hosts = ["registry.npmjs.org"];
  assert.throws(() => verifyReviewedPhalaSdkRuntimeCapsuleMaterial({ ...bytes, registryEvidenceBytes: canonical(falseClaim) }), /reviewed pin/u);
});

function auditInputs() {
  const authority = JSON.parse(material().authorityBytes);
  const reference = authority.registry_evidence.audit_inputs;
  const directory = path.dirname(path.join(ROOT, reference.path));
  const files = new Map();
  const walk = (relative = "") => {
    for (const name of fs.readdirSync(path.join(directory, relative))) {
      const filename = path.join(relative, name);
      const absolute = path.join(directory, filename);
      const stat = fs.lstatSync(absolute);
      assert.equal(stat.isSymbolicLink(), false);
      if (stat.isDirectory()) walk(filename);
      else {
        assert.equal(stat.isFile(), true);
        assert.equal(stat.nlink, 1);
        assert.equal(stat.mode & 0o022, 0);
        if (filename !== "file-manifest.json") files.set(filename.split(path.sep).join("/"), fs.readFileSync(absolute));
      }
    }
  };
  walk();
  return { reference, bytes: read(reference.path), files };
}

function verifyAuditInputs({ reference, bytes, files }) {
  assert.equal(reference.truth_status, "reviewed_source_evidence_not_runtime_reverification");
  assert.equal(reference.sha256, PHALA_SDK_REGISTRY_AUDIT_INPUT_MANIFEST_SHA256);
  assert.equal(sha256(bytes), reference.sha256);
  const manifest = JSON.parse(bytes);
  assert.deepEqual(bytes, canonical(manifest));
  assert.equal(manifest.truth_status, reference.truth_status);
  assert.deepEqual([...files.keys()].sort(), manifest.files.map(({ path: relative }) => relative));
  for (const entry of manifest.files) {
    const content = files.get(entry.path);
    assert.equal(content.length, entry.byte_length);
    assert.equal(sha256(content), entry.sha256);
  }
  return manifest;
}

test("source audit pins every exact npm and signed TUF input without making runtime network calls", () => {
  const audit = auditInputs();
  const manifest = verifyAuditInputs(audit);
  assert.equal(manifest.files.length, 30);
  assert.deepEqual(audit.files.get("upstream-registry-evidence.json"), material().registryEvidenceBytes);
  const seed = JSON.parse(audit.files.get("trust-seed/root-12.json"));
  const first = JSON.parse(audit.files.get("raw/8-%2F13.root.json.response"));
  const second = JSON.parse(audit.files.get("raw/9-%2F14.root.json.response"));
  const final = JSON.parse(audit.files.get("tuf-final/root.json"));
  assert.deepEqual([seed, first, second, final].map((root) => root.signed.version), [12, 13, 14, 15]);
  for (const root of [seed, first, second, final]) assert.ok(root.signatures.length > 0);
  const identity = JSON.parse(audit.files.get("verification-inputs.json"));
  assert.equal(sha256(audit.files.get("helpers/verify-public-registry.mjs")), identity.helper.sha256);
  assert.equal(sha256(audit.files.get("trust-seed/sigstore-tuf-3.1.1-seeds.json")), identity.installed_tuf_seed_sha256);
});

test("source audit rejects altered raw trust inputs, manifest digests, and extra files", () => {
  const audit = auditInputs();
  const changedFiles = new Map(audit.files);
  const root = Buffer.from(changedFiles.get("tuf-final/root.json"));
  root[100] ^= 1;
  changedFiles.set("tuf-final/root.json", root);
  assert.throws(() => verifyAuditInputs({ ...audit, files: changedFiles }));
  const changedManifest = Buffer.from(audit.bytes);
  changedManifest[100] ^= 1;
  assert.throws(() => verifyAuditInputs({ ...audit, bytes: changedManifest }));
  const extra = new Map(audit.files).set("unexpected.json", Buffer.from("{}"));
  assert.throws(() => verifyAuditInputs({ ...audit, files: extra }));
});

test("tracked rebuild recipe, lock, report, and I/O stubs match the reviewed authority", () => {
  const authority = JSON.parse(material().authorityBytes);
  const recipe = authority.build.recipe;
  assert.equal(sha256(read(recipe.path)), recipe.sha256);
  assert.equal(sha256(read(recipe.package_manifest_path)), recipe.package_manifest_sha256);
  assert.equal(sha256(read(recipe.package_lock_path)), recipe.package_lock_sha256);
  const recordReference = authority.build.review_build_record;
  const recordBytes = read(recordReference.path);
  assert.equal(sha256(recordBytes), recordReference.sha256);
  const record = JSON.parse(recordBytes);
  assert.equal(record.capsule.sha256, PHALA_SDK_RUNTIME_CAPSULE_SHA256);
  assert.deepEqual(record.capsule.exports, [...PHALA_REVIEWED_CAPSULE_EXPORTS]);
  assert.equal(record.build.two_independent_builds_identical, true);
  const lock = JSON.parse(read(recipe.package_lock_path));
  assert.equal(lock.packages["node_modules/@phala/cloud"].version, "0.4.0");
  assert.equal(lock.packages["node_modules/@phala/dstack-sdk"].version, "0.5.8");
  for (const stub of ["debug", "mitt", "ofetch"]) {
    assert.deepEqual(read(`scripts/vendor/phala-sdk-capsule-build/${stub}-stub.mjs`),
      read(`scripts/vendor/phala-sdk-runtime-capsule-${stub}-stub.mjs`));
  }
});
