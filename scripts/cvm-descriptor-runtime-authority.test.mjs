import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  link,
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { IMAGE_NAMES } from "./build-tee-image-release.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  PHALA_CVM_APP_COMPOSE_NAMES,
  createPhalaDstackComposeHashInput,
  phalaDstackComposeHash,
} from "./cvm-launch-intent-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
} from "./cvm-release-descriptor-set.mjs";
import {
  CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES,
  CVM_DESCRIPTOR_STABLE_READ_POLICY,
  assertFreshCvmDescriptorRuntimeAuthority,
  assertFreshCvmDescriptorRuntimeMaterials,
  canonicalCvmDescriptorRuntimeAuthorityText,
  createFreshCvmDescriptorRuntimeAuthority,
  cvmDescriptorRuntimeAuthoritySha256,
  normalizeCvmDescriptorRuntimeAuthority,
  readFreshCvmDescriptorRuntimeMaterials,
} from "./cvm-descriptor-runtime-authority.mjs";

const RELEASE_SHA = "a".repeat(40);
const SOURCE_REF = "refs/heads/main";
const GENERATED_AT = "2026-07-21T12:00:00.000Z";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonical(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function imageManifest() {
  return {
    schema: "dnai.tee-image-release.v1",
    release_sha: RELEASE_SHA,
    source_ref: SOURCE_REF,
    generated_at: GENERATED_AT,
    source_repository: "therealwiki/dnai-wikigen",
    signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
    workflow_run_id: "123456",
    workflow_run_url: "https://github.com/therealwiki/dnai-wikigen/actions/runs/123456",
    platform: "linux/amd64",
    images: IMAGE_NAMES.map((name, index) => {
      const digest = `sha256:${(index + 1).toString(16).repeat(64)}`;
      const repository = `ghcr.io/therealwiki/dnai-wikigen/${name}`;
      return {
        name,
        repository,
        digest,
        image: `${repository}@${digest}`,
        platform: "linux/amd64",
        sbom_artifact: {
          filename: `${name}.spdx.json`,
          sha256: (index + 6).toString(16).repeat(64),
        },
        provenance_subject: { name: repository, digest },
        attestations: {
          provenance: {
            predicate_type: "https://slsa.dev/provenance/v1",
            id: String(index + 1),
            url: `https://github.com/therealwiki/dnai-wikigen/attestations/${index + 1}`,
          },
          sbom: {
            predicate_type: "https://spdx.dev/Document/v2.3",
            id: String(index + 11),
            url: `https://github.com/therealwiki/dnai-wikigen/attestations/${index + 11}`,
          },
        },
        verification: {
          repo: "therealwiki/dnai-wikigen",
          signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
          source_digest: RELEASE_SHA,
          source_ref: SOURCE_REF,
          provenance_attestation: "verified",
          sbom_attestation: "verified",
        },
      };
    }),
  };
}

function serviceImageName(domain, service) {
  if (domain.endsWith("_qvl_cvm")) return "attestation-qvl";
  if (domain === "independent_metering_cvm") return "compute-metering";
  if (service === "neko") return "neko-chrome";
  if (service === "oracle") return "tee-email-oracle";
  return "tinker-delegate";
}

function mainProfile(service) {
  if (["arena-policy-init", "arena-worker"].includes(service)) return "arena-runtime";
  if (service === "anchor-writer-evidence") return "anchor-writer-ceremony";
  if (service === "deal-runtime") return "deal-settlement";
  if (service === "compute-execution-worker") return "compute-execution";
  return null;
}

function descriptorDocument(domain, manifest) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const services = Object.fromEntries(
    CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain].map((service) => {
      const imageName = serviceImageName(domain, service);
      const spec = {
        image: manifest.images.find((image) => image.name === imageName).image,
        platform: "linux/amd64",
      };
      if (!policy.launch_settings.initial_services.includes(service)) {
        spec.profiles = [domain === "main_runtime_cvm"
          ? mainProfile(service)
          : (domain.endsWith("_qvl_cvm") ? "qvl-runtime" : "metering-runtime")];
      }
      return [service, spec];
    }),
  );
  const defaulted = new Set(
    policy.public_environment_key_classification.descriptor_defaulted_keys,
  );
  const bootstrapAndProvisioning = new Set([
    ...policy.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    ...policy.public_environment_key_classification.provisioning_result_keys,
  ]);
  const late = new Set([
    ...policy.public_environment_key_classification.post_measurement_deferred_keys,
    ...Object.entries(policy.encrypted_secret_environment_keys_by_phase)
      .filter(([phase]) => phase !== "bootstrap_provision")
      .flatMap(([, keys]) => keys),
  ]);
  const references = [...new Set([
    ...policy.exact_allowed_environment_keys.filter((key) => key !== "COMPOSE_PROFILES"),
    ...defaulted,
  ])].sort();
  const activeTarget = policy.launch_settings.initial_services[0]
    || CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain][0];
  const lateTarget = CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain]
    .find((service) => !policy.launch_settings.initial_services.includes(service));
  for (const key of references) {
    const target = domain === "main_runtime_cvm"
      && CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS.includes(key)
      ? "delegate"
      : late.has(key) ? lateTarget : activeTarget;
    services[target].environment ||= {};
    services[target].environment[key] = late.has(key)
      ? `\${${key}:-}`
      : bootstrapAndProvisioning.has(key)
        ? `\${${key}:?fixture requires ${key}}`
        : defaulted.has(key)
          ? `\${${key}:-fixture-default}`
          : `\${${key}:?fixture requires ${key}}`;
  }
  return {
    name: PHALA_CVM_APP_COMPOSE_NAMES[domain],
    services,
    "x-dnai-release": {
      schema: "dnai.cvm-topology.v6",
      release_sha: RELEASE_SHA,
      source_ref: SOURCE_REF,
      platform: "linux/amd64",
      trust_domain: domain,
      deployment_status: "rendered_not_deployed",
    },
  };
}

function descriptorText(document, manifestSha) {
  return [
    "# Generated by tinker-release-composes. Do not edit by hand.",
    `# Input image manifest sha256: ${manifestSha}`,
    "# Status: rendered_not_deployed; deployment and TDX verification are separate gates.",
    canonical(document).trimEnd(),
    "",
  ].join("\n");
}

async function buildFixture() {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-runtime-authority-")));
  const releaseDirectory = path.join(root, ".release");
  await mkdir(releaseDirectory, { mode: 0o700 });
  const manifest = imageManifest();
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const manifestSha = sha256(manifestText);
  const bundleText = '{"fixture":"attestation-bundle"}\n';
  const deploymentIntentText = '{"fixture":"deployment-intent"}\n';
  await Promise.all([
    writeFile(path.join(releaseDirectory, "dnai-tee-image-release.json"), manifestText),
    writeFile(path.join(releaseDirectory, "dnai-tee-image-release.bundle.json"), bundleText),
    writeFile(path.join(releaseDirectory, "dnai-deployment-intent-core.json"), deploymentIntentText),
  ]);
  const documents = {};
  const descriptorBytes = {};
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const document = descriptorDocument(domain, manifest);
    const text = descriptorText(document, manifestSha);
    documents[domain] = document;
    descriptorBytes[domain] = text;
    await writeFile(path.join(releaseDirectory, CVM_LAUNCH_DESCRIPTOR_FILES[domain]), text);
  }
  const trustDomains = Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => {
    const services = CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain];
    return [domain, {
      compose: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
      sha256: sha256(descriptorBytes[domain]),
      services,
      images: [...new Set(services.map((service) => (
        manifest.images.find((image) => image.name === serviceImageName(domain, service)).image
      )))],
    }];
  }));
  const topology = {
    schema: "dnai.cvm-topology.v6",
    status: "rendered_not_deployed",
    release_sha: RELEASE_SHA,
    source_ref: SOURCE_REF,
    generated_at: GENERATED_AT,
    deploymentIntentSha256: `sha256:${sha256(deploymentIntentText)}`,
    deploymentIntent: {
      file: "dnai-deployment-intent-core.json",
      sha256: sha256(deploymentIntentText),
      schema: "dnai.deployment-intent-core.v6",
    },
    image_manifest: {
      file: "dnai-tee-image-release.json",
      sha256: manifestSha,
      schema: "dnai.tee-image-release.v1",
    },
    image_manifest_attestation: {
      file: "dnai-tee-image-release.bundle.json",
      sha256: sha256(bundleText),
      predicate_type: "https://slsa.dev/provenance/v1",
    },
    trust_domains: trustDomains,
    checks: {
      literal_digest_pins: true,
      linux_amd64_only: true,
      local_build_contexts: false,
      seven_cvm_descriptors: true,
      purpose_separated_qvl_descriptors: true,
      raw_secret_values_embedded: false,
      deployment_attempted: false,
      tdx_verification_claimed: false,
    },
  };
  await writeFile(path.join(releaseDirectory, "dnai-cvm-topology.json"), canonical(topology));
  return { root, releaseDirectory, documents, descriptorBytes, topology, manifestSha };
}

async function rewriteDescriptor(fixture, domain, document) {
  const text = descriptorText(document, fixture.manifestSha);
  const file = path.join(fixture.releaseDirectory, CVM_LAUNCH_DESCRIPTOR_FILES[domain]);
  await writeFile(file, text);
  fixture.topology.trust_domains[domain].sha256 = sha256(text);
  fixture.topology.trust_domains[domain].services = Object.keys(document.services);
  fixture.topology.trust_domains[domain].images = [...new Set(
    Object.values(document.services).map((service) => service.image),
  )];
  await writeFile(
    path.join(fixture.releaseDirectory, "dnai-cvm-topology.json"),
    canonical(fixture.topology),
  );
}

test("fresh authority stable-reads exact seven descriptors and privately brands exact runtime facts", async () => {
  const fixture = await buildFixture();
  try {
    const authority = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    assert.equal(authority.schema, CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA);
    assert.equal(authority.descriptors.length, 7);
    assert.deepEqual(authority.stable_read_policy, CVM_DESCRIPTOR_STABLE_READ_POLICY);
    assert.deepEqual(authority.fact_sources, CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES);
    assert.deepEqual(
      authority.external_runtime_authority_requirements,
      CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
    );
    assert.equal(authority.invariants.runtime_resource_or_identity_claimed, false);
    assert.equal(authority.invariants.deployment_or_tdx_claimed, false);
    assert.match(cvmDescriptorRuntimeAuthoritySha256(authority), /^sha256:[0-9a-f]{64}$/);
    assert.equal(
      canonicalCvmDescriptorRuntimeAuthorityText(authority),
      canonicalCvmDescriptorRuntimeAuthorityText(normalizeCvmDescriptorRuntimeAuthority(authority)),
    );
    assert.equal(
      assertFreshCvmDescriptorRuntimeAuthority(authority, {
        expectedReleaseSha: RELEASE_SHA,
        expectedDescriptorSetReceiptSha256: authority.descriptor_set_receipt_sha256,
      }),
      authority,
    );
    const materials = await readFreshCvmDescriptorRuntimeMaterials({
      authority,
      releaseDirectory: fixture.releaseDirectory,
    });
    assert.equal(
      assertFreshCvmDescriptorRuntimeMaterials(materials, { authority }),
      materials,
    );
    assert.deepEqual(materials.map(({ domain }) => domain), CVM_LAUNCH_DOMAINS);
    assert.throws(
      () => assertFreshCvmDescriptorRuntimeMaterials(structuredClone(materials), { authority }),
      /do not match their branded authority/,
    );
    for (const entry of authority.descriptors) {
      const file = await readFile(
        path.join(fixture.releaseDirectory, CVM_LAUNCH_DESCRIPTOR_FILES[entry.domain]),
        "utf8",
      );
      const expectedHash = phalaDstackComposeHash(createPhalaDstackComposeHashInput(
        CVM_LAUNCH_DESCRIPTOR_POLICY[entry.domain].app_compose_candidate,
        file,
        CVM_LAUNCH_DESCRIPTOR_POLICY[entry.domain].exact_allowed_environment_keys,
      ));
      assert.equal(entry.app_compose_hash, expectedHash);
      assert.equal(authority.app_compose_hash_by_domain[entry.domain], expectedHash);
      assert.equal(
        entry.descriptor_sha256,
        `sha256:${sha256(Buffer.from(file, "utf8"))}`,
      );
      const material = materials.find(({ domain }) => domain === entry.domain);
      assert.equal(material.docker_compose_file, file);
      assert.equal(material.app_compose_hash, entry.app_compose_hash);
    }
    assert.throws(() => { authority.descriptors[0].app_compose_hash = "f".repeat(64); }, TypeError);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("normalization never mints the private stable-read brand", async () => {
  const fixture = await buildFixture();
  try {
    const authority = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    const normalizedClone = normalizeCvmDescriptorRuntimeAuthority(structuredClone(authority));
    assert.deepEqual(normalizedClone, authority);
    assert.throws(
      () => assertFreshCvmDescriptorRuntimeAuthority(normalizedClone),
      /privately branded fresh stable-read/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("same caller hash label cannot associate different compose or policy facts", async () => {
  const fixture = await buildFixture();
  try {
    const authority = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    const forged = structuredClone(authority);
    forged.descriptors[0].app_compose_hash = "f".repeat(64);
    forged.app_compose_hash_by_domain.main_runtime_cvm = "f".repeat(64);
    assert.throws(
      () => normalizeCvmDescriptorRuntimeAuthority(forged),
      /runtime facts are not bound/,
    );
    const policyForgery = structuredClone(authority);
    policyForgery.descriptors[0].phase_policy.initial_phase = "final_authority_runtime";
    assert.throws(
      () => normalizeCvmDescriptorRuntimeAuthority(policyForgery),
      /environment, phase, or privacy policy drifted/,
    );
    assert.throws(
      () => assertFreshCvmDescriptorRuntimeAuthority(structuredClone(authority)),
      /privately branded fresh stable-read/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("substituted descriptor bytes produce a different exact binding and cannot satisfy the old authority", async () => {
  const fixture = await buildFixture();
  try {
    const first = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    const changed = structuredClone(fixture.documents.main_runtime_cvm);
    changed["x-runtime-authority-adversarial-byte-substitution"] = true;
    await rewriteDescriptor(fixture, "main_runtime_cvm", changed);
    const second = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    assert.notEqual(
      second.descriptor_sha256_by_domain.main_runtime_cvm,
      first.descriptor_sha256_by_domain.main_runtime_cvm,
    );
    assert.notEqual(
      second.app_compose_hash_by_domain.main_runtime_cvm,
      first.app_compose_hash_by_domain.main_runtime_cvm,
    );
    assert.notEqual(second.descriptor_runtime_facts_sha256, first.descriptor_runtime_facts_sha256);
    assert.notEqual(second.descriptor_set_receipt_sha256, first.descriptor_set_receipt_sha256);
    assert.throws(
      () => assertFreshCvmDescriptorRuntimeAuthority(second, {
        expectedDescriptorSetReceiptSha256: first.descriptor_set_receipt_sha256,
      }),
      /expected binding failed/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("unchanged stable reads preserve deterministic runtime facts while freshness receipts rotate", async () => {
  const fixture = await buildFixture();
  try {
    const first = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    const second = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    assert.equal(second.descriptor_runtime_facts_sha256, first.descriptor_runtime_facts_sha256);
    assert.deepEqual(second.descriptor_sha256_by_domain, first.descriptor_sha256_by_domain);
    assert.deepEqual(second.app_compose_hash_by_domain, first.app_compose_hash_by_domain);
    assert.equal(second.descriptor_set_receipt_sha256, first.descriptor_set_receipt_sha256);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("symlink, hard-link, and writable descriptor substitutions fail closed", async (t) => {
  await t.test("symbolic link", async () => {
    const fixture = await buildFixture();
    try {
      const file = path.join(
        fixture.releaseDirectory,
        CVM_LAUNCH_DESCRIPTOR_FILES.arena_qvl_cvm,
      );
      const target = path.join(fixture.root, "substituted-arena.json");
      await rename(file, target);
      await symlink(target, file);
      await assert.rejects(
        createFreshCvmDescriptorRuntimeAuthority({
          releaseDirectory: fixture.releaseDirectory,
          expectedReleaseSha: RELEASE_SHA,
        }),
        /symbolic links|path must not contain/,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  await t.test("hard link", async () => {
    const fixture = await buildFixture();
    try {
      const file = path.join(
        fixture.releaseDirectory,
        CVM_LAUNCH_DESCRIPTOR_FILES.anchor_writer_qvl_cvm,
      );
      await link(file, path.join(fixture.root, "second-hard-link"));
      await assert.rejects(
        createFreshCvmDescriptorRuntimeAuthority({
          releaseDirectory: fixture.releaseDirectory,
          expectedReleaseSha: RELEASE_SHA,
        }),
        /bounded nonempty regular file|link-safe/,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  await t.test("group/world writable", async () => {
    const fixture = await buildFixture();
    try {
      const file = path.join(
        fixture.releaseDirectory,
        CVM_LAUNCH_DESCRIPTOR_FILES.compute_metering_qvl_cvm,
      );
      await chmod(file, 0o666);
      await assert.rejects(
        createFreshCvmDescriptorRuntimeAuthority({
          releaseDirectory: fixture.releaseDirectory,
          expectedReleaseSha: RELEASE_SHA,
        }),
        /bounded nonempty regular file|non-writable-by-group-or-world/,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
});

test("concurrent descriptor replacement during validation/read is detected and never branded", async () => {
  const fixture = await buildFixture();
  try {
    const file = path.join(
      fixture.releaseDirectory,
      CVM_LAUNCH_DESCRIPTOR_FILES.main_runtime_cvm,
    );
    const original = await readFile(file);
    const changedDocument = structuredClone(fixture.documents.main_runtime_cvm);
    changedDocument["x-concurrent-toctou-substitution"] = true;
    const changed = Buffer.from(descriptorText(changedDocument, fixture.manifestSha), "utf8");
    const pending = createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    await writeFile(file, changed);
    await assert.rejects(
      pending,
      /changed during|changed after|does not bind|body is not canonical|metadata is not exact|descriptor release metadata|service matrix|topology/,
    );
    await writeFile(file, original);
    assert.throws(
      () => assertFreshCvmDescriptorRuntimeAuthority({}),
      /privately branded fresh stable-read/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});
