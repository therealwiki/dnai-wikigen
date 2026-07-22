import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  CVM_LAUNCH_DOMAINS,
} from "./cvm-launch-intent-core.mjs";
import * as descriptorCore from "./cvm-descriptor-runtime-authority-core.mjs";
import * as descriptorFacade from "./cvm-descriptor-runtime-authority.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX as constantsServiceMatrix,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA as constantsReceiptSchema,
} from "./cvm-release-descriptor-set-constants.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX as facadeServiceMatrix,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA as facadeReceiptSchema,
} from "./cvm-release-descriptor-set.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

function localModuleClosure(entrypoint) {
  const seen = new Set();
  function visit(filename) {
    const resolved = fs.realpathSync(filename);
    if (seen.has(resolved)) return;
    seen.add(resolved);
    const source = fs.readFileSync(resolved, "utf8");
    assert.doesNotMatch(source, /from\s+["']node:(?:fs|path)(?:\/[^"']*)?["']/);
    assert.doesNotMatch(source, /\bWeakMap\b/);
    assert.doesNotMatch(source, /\bDate\.now\s*\(/);
    assert.doesNotMatch(source, /\bprocess\s*\./);
    for (const match of source.matchAll(/from\s+["'](\.\.?\/[^"']+)["']/g)) {
      const dependency = path.resolve(path.dirname(resolved), match[1]);
      if (dependency.startsWith(HERE) && dependency.endsWith(".mjs")) visit(dependency);
    }
  }
  visit(entrypoint);
  return [...seen].sort();
}

test("descriptor runtime authority core and its local closure are effect-free leaves", () => {
  const corePath = fileURLToPath(
    new URL("./cvm-descriptor-runtime-authority-core.mjs", import.meta.url),
  );
  const closure = localModuleClosure(corePath);
  assert.ok(closure.includes(corePath));
  assert.ok(closure.some((entry) => entry.endsWith("cvm-launch-intent-core.mjs")));
  assert.ok(closure.some((entry) => entry.endsWith("canonical-authority-graph.mjs")));

  const releaseCorePath = fileURLToPath(new URL(
    "./phala-seven-cvm-release-verification-authority-core.mjs",
    import.meta.url,
  ));
  const releaseClosure = localModuleClosure(releaseCorePath);
  assert.ok(releaseClosure.includes(corePath));
  const releaseCoreSource = fs.readFileSync(releaseCorePath, "utf8");
  assert.match(
    releaseCoreSource,
    /from "\.\/cvm-descriptor-runtime-authority-core\.mjs"/,
  );
  assert.doesNotMatch(
    releaseCoreSource,
    /from "\.\/cvm-descriptor-runtime-authority\.mjs"/,
  );
  assert.equal(pathToFileURL(corePath).protocol, "file:");
});

test("descriptor-set constants have one pure source and preserve facade exports", () => {
  assert.equal(facadeReceiptSchema, constantsReceiptSchema);
  assert.deepEqual(facadeServiceMatrix, constantsServiceMatrix);
  assert.deepEqual(Object.keys(constantsServiceMatrix), CVM_LAUNCH_DOMAINS);
});

test("core normalization is digest-identical while fixture values remain unbranded", () => {
  const releaseAuthority =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  const descriptorAuthority = releaseAuthority.cvm_descriptor_runtime_authority;
  const normalized = descriptorCore.normalizeCvmDescriptorRuntimeAuthority(
    descriptorAuthority,
  );
  assert.equal(
    descriptorCore.cvmDescriptorRuntimeAuthoritySha256(normalized),
    descriptorFacade.cvmDescriptorRuntimeAuthoritySha256(descriptorAuthority),
  );
  assert.equal(
    descriptorCore.canonicalCvmDescriptorRuntimeAuthorityText(normalized),
    descriptorFacade.canonicalCvmDescriptorRuntimeAuthorityText(descriptorAuthority),
  );
  assert.throws(
    () => descriptorFacade.assertFreshCvmDescriptorRuntimeAuthority(descriptorAuthority),
    /privately branded fresh stable-read descriptor runtime authority is required/,
  );
});

test("canonical release descriptor helper overrides only the main domain", () => {
  const mainRuntime = {
    descriptor_sha256: `sha256:${"d1".repeat(32)}`,
    app_id: "d2".repeat(20),
    cvm_id: "synthetic-main-override-01",
    compose_hash: "d3".repeat(32),
    os_image_hash: "d4".repeat(32),
  };
  const descriptors = syntheticPhalaSevenCvmReleaseDescriptorsFixture({ mainRuntime });
  assert.deepEqual(descriptors.map(({ domain }) => domain), CVM_LAUNCH_DOMAINS);
  assert.deepEqual(
    Object.fromEntries(Object.keys(mainRuntime).map((key) => [key, descriptors[0][key]])),
    mainRuntime,
  );
  assert.throws(
    () => syntheticPhalaSevenCvmReleaseDescriptorsFixture({
      mainRuntime: { ceremony_nonce: `0x${"d5".repeat(32)}` },
    }),
    /unsupported fixture field/,
  );
});
