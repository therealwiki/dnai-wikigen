import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BUILD_DESCRIPTOR_SCHEMA,
  IMAGE_NAMES,
  PLATFORM,
  RELEASE_SCHEMA,
  createBuildDescriptor,
  createReleaseManifest,
  createVerificationPlan,
  main,
  normalizeBuildDescriptor,
} from "./build-tee-image-release.mjs";

const SHA = "a".repeat(40);
const SOURCE_REPOSITORY = "therealwiki/dnai-wikigen";
const SOURCE_REF = "refs/heads/main";
const SIGNER_WORKFLOW = `${SOURCE_REPOSITORY}/.github/workflows/build-tee-images.yml`;
const GENERATED_AT = "2026-07-15T12:00:00.000Z";

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "dnai-tee-image-release-"));
  const descriptors = path.join(root, "descriptors");
  const verifications = path.join(root, "verifications");
  const sboms = path.join(root, "sboms");
  await Promise.all([mkdir(descriptors), mkdir(verifications), mkdir(sboms)]);
  return { root, descriptors, verifications, sboms };
}

async function writeSbom(root, name) {
  const filePath = path.join(root, `${name}.spdx.json`);
  await writeFile(filePath, JSON.stringify({
    spdxVersion: "SPDX-2.3",
    SPDXID: "SPDXRef-DOCUMENT",
    name,
    packages: [],
  }));
  return filePath;
}

async function descriptor(root, name, index, overrides = {}) {
  const digest = `sha256:${String(index + 1).repeat(64)}`;
  const repository = `ghcr.io/${SOURCE_REPOSITORY}/${name}`;
  const value = await createBuildDescriptor({
    name,
    repository,
    digest,
    platform: PLATFORM,
    sourceRepository: SOURCE_REPOSITORY,
    releaseSha: SHA,
    sourceRef: SOURCE_REF,
    signerWorkflow: SIGNER_WORKFLOW,
    provenanceId: String(1000 + index),
    provenanceUrl: `https://github.com/${SOURCE_REPOSITORY}/attestations/${1000 + index}`,
    sbomId: String(2000 + index),
    sbomUrl: `https://github.com/${SOURCE_REPOSITORY}/attestations/${2000 + index}`,
    sbomPath: await writeSbom(root, name),
    ...overrides,
  });
  return value;
}

function verification(value, overrides = {}) {
  return {
    image: value.image.image,
    repo: SOURCE_REPOSITORY,
    signer_workflow: SIGNER_WORKFLOW,
    source_digest: SHA,
    source_ref: SOURCE_REF,
    provenance_attestation: "verified",
    sbom_attestation: "verified",
    raw_secret_egress: false,
    ...overrides,
  };
}

async function populate(sboms, descriptors, verifications) {
  const values = [];
  for (const [index, name] of IMAGE_NAMES.entries()) {
    const value = await descriptor(sboms, name, index);
    values.push(value);
    // Deliberately reverse file names: aggregate order must be canonical, not
    // filesystem-dependent.
    const prefix = String(IMAGE_NAMES.length - index);
    await writeFile(path.join(descriptors, `${prefix}-${name}.json`), `${JSON.stringify(value)}\n`);
    await writeFile(path.join(verifications, `${prefix}-${name}.json`), `${JSON.stringify(verification(value))}\n`);
  }
  return values;
}

test("build descriptor binds the exact image, source, SBOM, and GitHub attestations", async () => {
  const { root } = await fixture();
  const value = await descriptor(root, "tinker-delegate", 0);
  assert.equal(value.schema, BUILD_DESCRIPTOR_SCHEMA);
  assert.equal(value.release_sha, SHA);
  assert.equal(value.image.platform, PLATFORM);
  assert.equal(value.image.repository, `ghcr.io/${SOURCE_REPOSITORY}/tinker-delegate`);
  assert.equal(value.image.image, `${value.image.repository}@${value.image.digest}`);
  assert.match(value.image.sbom_artifact.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(value.image.provenance_subject, {
    name: value.image.repository,
    digest: value.image.digest,
  });
  assert.equal(value.image.attestations.provenance.predicate_type, "https://slsa.dev/provenance/v1");
  assert.equal(value.image.attestations.sbom.predicate_type, "https://spdx.dev/Document/v2.3");
});

test("descriptor rejects unsupported images, mutable references, wrong platform, and non-SPDX input", async () => {
  const { root } = await fixture();
  const sbomPath = await writeSbom(root, "tinker-delegate");
  const base = {
    name: "tinker-delegate",
    repository: `ghcr.io/${SOURCE_REPOSITORY}/tinker-delegate`,
    digest: `sha256:${"1".repeat(64)}`,
    platform: PLATFORM,
    sourceRepository: SOURCE_REPOSITORY,
    releaseSha: SHA,
    sourceRef: SOURCE_REF,
    signerWorkflow: SIGNER_WORKFLOW,
    provenanceId: "1",
    provenanceUrl: `https://github.com/${SOURCE_REPOSITORY}/attestations/1`,
    sbomId: "2",
    sbomUrl: `https://github.com/${SOURCE_REPOSITORY}/attestations/2`,
    sbomPath,
  };
  await assert.rejects(createBuildDescriptor({ ...base, name: "debug-helper" }), /unsupported production image/);
  await assert.rejects(createBuildDescriptor({ ...base, digest: "latest" }), /sha256 digest/);
  await assert.rejects(createBuildDescriptor({ ...base, platform: "linux/arm64" }), /linux\/amd64/);
  await writeFile(sbomPath, JSON.stringify({ spdxVersion: "SPDX-2.2", SPDXID: "SPDXRef-DOCUMENT" }));
  await assert.rejects(createBuildDescriptor(base), /SPDX 2\.3/);
});

test("release manifest has exact source-bound metadata and canonical five-image order", async () => {
  const { descriptors, verifications, sboms } = await fixture();
  await populate(sboms, descriptors, verifications);
  const value = await createReleaseManifest({
    descriptorsDirectory: descriptors,
    verificationsDirectory: verifications,
    sbomsDirectory: sboms,
    generatedAt: GENERATED_AT,
    workflowRunId: "12345",
    workflowRunUrl: `https://github.com/${SOURCE_REPOSITORY}/actions/runs/12345`,
  });

  assert.equal(value.schema, RELEASE_SCHEMA);
  assert.equal(value.release_sha, SHA);
  assert.equal(value.source_ref, SOURCE_REF);
  assert.equal(value.generated_at, GENERATED_AT);
  assert.equal(value.platform, PLATFORM);
  assert.deepEqual(value.images.map((image) => image.name), IMAGE_NAMES);
  assert.equal(new Set(value.images.map((image) => image.image)).size, IMAGE_NAMES.length);
  for (const image of value.images) {
    assert.deepEqual(Object.keys(image.verification), [
      "repo",
      "signer_workflow",
      "source_digest",
      "source_ref",
      "provenance_attestation",
      "sbom_attestation",
    ]);
    assert.equal(image.verification.provenance_attestation, "verified");
    assert.equal(image.verification.sbom_attestation, "verified");
    assert.equal(image.provenance_subject.name, image.repository);
    assert.equal(image.provenance_subject.digest, image.digest);
  }
});

test("verification plan is canonical and carries only exact verifier inputs", async () => {
  const { descriptors, verifications, sboms } = await fixture();
  await populate(sboms, descriptors, verifications);
  const plan = await createVerificationPlan(descriptors);
  assert.deepEqual(plan.map((entry) => entry.name), IMAGE_NAMES);
  assert.deepEqual(Object.keys(plan[0]), [
    "name",
    "image",
    "repo",
    "signer_workflow",
    "source_digest",
    "source_ref",
  ]);
  assert.equal(plan[0].source_digest, SHA);
  assert.equal(plan[0].source_ref, SOURCE_REF);
});

test("release aggregation verifies the exact five downloaded SPDX artifacts", async () => {
  const { descriptors, verifications, sboms } = await fixture();
  await populate(sboms, descriptors, verifications);
  const input = {
    descriptorsDirectory: descriptors,
    verificationsDirectory: verifications,
    sbomsDirectory: sboms,
    generatedAt: GENERATED_AT,
    workflowRunId: "12345",
    workflowRunUrl: `https://github.com/${SOURCE_REPOSITORY}/actions/runs/12345`,
  };
  const name = IMAGE_NAMES[0];
  const sbomPath = path.join(sboms, `${name}.spdx.json`);

  await writeFile(sbomPath, JSON.stringify({
    spdxVersion: "SPDX-2.3",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "tampered",
    packages: [],
  }));
  await assert.rejects(createReleaseManifest(input), /downloaded SBOM sha256 mismatch/);

  await writeSbom(sboms, name);
  await writeFile(sbomPath, JSON.stringify({ spdxVersion: "SPDX-2.2", SPDXID: "SPDXRef-DOCUMENT" }));
  await assert.rejects(createReleaseManifest(input), /must be an SPDX 2\.3 JSON document/);

  await writeSbom(sboms, name);
  await rm(sbomPath);
  await assert.rejects(createReleaseManifest(input), /exactly the five canonical regular SPDX JSON files/);

  await writeSbom(sboms, name);
  await writeFile(path.join(sboms, "unexpected.spdx.json"), "{}\n");
  await assert.rejects(createReleaseManifest(input), /exactly the five canonical regular SPDX JSON files/);
  await rm(path.join(sboms, "unexpected.spdx.json"));

  await rm(sbomPath);
  await symlink(path.join(sboms, `${IMAGE_NAMES[1]}.spdx.json`), sbomPath);
  await assert.rejects(createReleaseManifest(input), /exactly the five canonical regular SPDX JSON files/);
});

test("release aggregation fails closed on branch images, missing images, and verification drift", async () => {
  const { descriptors, verifications, sboms } = await fixture();
  const values = await populate(sboms, descriptors, verifications);

  const branchDescriptorPath = path.join(descriptors, `5-${IMAGE_NAMES[0]}.json`);
  const branchDescriptor = JSON.parse(await readFile(branchDescriptorPath, "utf8"));
  branchDescriptor.source_ref = "refs/heads/codex/preview";
  await writeFile(branchDescriptorPath, JSON.stringify(branchDescriptor));
  await assert.rejects(createReleaseManifest({
    descriptorsDirectory: descriptors,
    verificationsDirectory: verifications,
    sbomsDirectory: sboms,
    generatedAt: GENERATED_AT,
    workflowRunId: "12345",
    workflowRunUrl: `https://github.com/${SOURCE_REPOSITORY}/actions/runs/12345`,
  }), /same source commit, ref, repository, and workflow/);

  for (const [index, name] of IMAGE_NAMES.entries()) {
    const filePath = path.join(descriptors, `${IMAGE_NAMES.length - index}-${name}.json`);
    const candidate = JSON.parse(await readFile(filePath, "utf8"));
    candidate.source_ref = "refs/heads/codex/preview";
    await writeFile(filePath, JSON.stringify(candidate));
  }
  await assert.rejects(createReleaseManifest({
    descriptorsDirectory: descriptors,
    verificationsDirectory: verifications,
    sbomsDirectory: sboms,
    generatedAt: GENERATED_AT,
    workflowRunId: "12345",
    workflowRunUrl: `https://github.com/${SOURCE_REPOSITORY}/actions/runs/12345`,
  }), /refs\/heads\/main/);

  for (const [index, name] of IMAGE_NAMES.entries()) {
    const filePath = path.join(descriptors, `${IMAGE_NAMES.length - index}-${name}.json`);
    const candidate = JSON.parse(await readFile(filePath, "utf8"));
    candidate.source_ref = SOURCE_REF;
    await writeFile(filePath, JSON.stringify(candidate));
  }
  const verificationPath = path.join(verifications, `5-${IMAGE_NAMES[0]}.json`);
  await writeFile(verificationPath, JSON.stringify(verification(values[0], { source_digest: "b".repeat(40) })));
  await assert.rejects(createReleaseManifest({
    descriptorsDirectory: descriptors,
    verificationsDirectory: verifications,
    sbomsDirectory: sboms,
    generatedAt: GENERATED_AT,
    workflowRunId: "12345",
    workflowRunUrl: `https://github.com/${SOURCE_REPOSITORY}/actions/runs/12345`,
  }), /verification identity mismatch/);

  await writeFile(path.join(descriptors, "unexpected.json"), "{}\n");
  await assert.rejects(createReleaseManifest({
    descriptorsDirectory: descriptors,
    verificationsDirectory: verifications,
    sbomsDirectory: sboms,
    generatedAt: GENERATED_AT,
    workflowRunId: "12345",
    workflowRunUrl: `https://github.com/${SOURCE_REPOSITORY}/actions/runs/12345`,
  }), /exactly 5 JSON files/);
});

test("normalizer rejects unreviewed fields and CLI writes the canonical manifest", async () => {
  const { root, descriptors, verifications, sboms } = await fixture();
  const values = await populate(sboms, descriptors, verifications);
  assert.throws(
    () => normalizeBuildDescriptor({ ...values[0], mutable_tag: "latest" }),
    /fields are not exact/,
  );

  const output = path.join(root, "dnai-tee-image-release.json");
  await main([
    "aggregate",
    "--descriptors", descriptors,
    "--verifications", verifications,
    "--sboms", sboms,
    "--generated-at", GENERATED_AT,
    "--workflow-run-id", "12345",
    "--workflow-run-url", `https://github.com/${SOURCE_REPOSITORY}/actions/runs/12345`,
    "--output", output,
  ]);
  const written = JSON.parse(await readFile(output, "utf8"));
  assert.equal(written.schema, RELEASE_SCHEMA);
  assert.deepEqual(written.images.map((image) => image.name), IMAGE_NAMES);
});
