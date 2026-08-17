import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, realpath, rm, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  PHALA_CVM_APP_COMPOSE_NAMES,
} from "./cvm-launch-intent-core.mjs";
import { IMAGE_NAMES } from "./build-tee-image-release.mjs";
import {
  assertTrackedDescriptorMaterializationSources,
  cvmReleaseDescriptorSetReceiptSha256,
  CVM_RELEASE_DESCRIPTOR_GENERATED_FILES,
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES,
  inspectTrackedDescriptorMaterializationSources,
  main,
  normalizeCvmReleaseDescriptorSetReceipt,
  validateCanonicalGeneratedCvmDescriptorSet,
  verifyExactTrackedSourceDescriptorReproduction,
} from "./cvm-release-descriptor-set-v3.mjs";

const RELEASE_SHA = "a".repeat(40);
const SOURCE_REF = "refs/heads/main";
const GENERATED_AT = "2026-07-21T12:00:00.000Z";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalSortedValue(value) {
  if (Array.isArray(value)) return value.map(canonicalSortedValue);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalSortedValue(value[key])]),
  );
}

function canonical(value) {
  return `${JSON.stringify(canonicalSortedValue(value), null, 2)}\n`;
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
  if (service === "oracle" || service === "mailbox-genesis") {
    return "tee-email-oracle";
  }
  return "tinker-delegate";
}

function mainProfile(service) {
  if (["arena-policy-init", "arena-worker"].includes(service)) return "arena-runtime";
  if (service === "anchor-writer-evidence") return "anchor-writer-ceremony";
  if (service === "deal-runtime") return "deal-settlement";
  if (service === "compute-execution-worker") return "compute-execution";
  if (service === "collaboration-execution-worker") {
    return "collaboration-execution";
  }
  if (service === "review-operations") return "review-operations";
  if (service === "mailbox-genesis") return "mailbox-genesis";
  if (service === "tinker-account-genesis") return "tinker-account-genesis";
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
        spec.profiles = [
          domain === "main_runtime_cvm"
            ? mainProfile(service)
            : (domain.endsWith("_qvl_cvm") ? "qvl-runtime" : "metering-runtime"),
        ];
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
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-descriptors-")));
  const releaseDirectory = path.join(root, ".release");
  await mkdir(releaseDirectory, { mode: 0o700 });
  const manifest = imageManifest();
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const manifestSha = sha256(manifestText);
  const bundleText = '{"fixture":"attestation-bundle"}\n';
  const deploymentIntentText = '{"fixture":"deployment-intent"}\n';
  const accountBindingCeremonyReceipt = {
    schema: "dnai.tinker-account-binding-ceremony-receipt.v1",
    tinker_account_binding_ceremony_receipt_sha256:
      `sha256:${"a".repeat(64)}`,
  };
  const accountBindingCeremonyReceiptText =
    `${JSON.stringify(accountBindingCeremonyReceipt, null, 2)}\n`;
  await Promise.all([
    writeFile(path.join(releaseDirectory, "dnai-tee-image-release.json"), manifestText),
    writeFile(path.join(releaseDirectory, "dnai-tee-image-release.bundle.json"), bundleText),
    writeFile(path.join(releaseDirectory, "dnai-deployment-intent-core.json"), deploymentIntentText),
    writeFile(
      path.join(
        releaseDirectory,
        "tinker-account-binding-ceremony.receipt.json",
      ),
      accountBindingCeremonyReceiptText,
    ),
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
    const images = [...new Set(services.map((service) => (
      manifest.images.find((image) => image.name === serviceImageName(domain, service)).image
    )))];
    return [domain, {
      compose: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
      sha256: sha256(descriptorBytes[domain]),
      services,
      images,
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
    tinkerAccountBindingCeremonyReceipt: {
      file: "tinker-account-binding-ceremony.receipt.json",
      sha256: sha256(accountBindingCeremonyReceiptText),
      schema: "dnai.tinker-account-binding-ceremony-receipt.v1",
      tinkerAccountBindingCeremonyReceiptSha256:
        accountBindingCeremonyReceipt
          .tinker_account_binding_ceremony_receipt_sha256,
      validation:
        "python_structural_and_domain_digest_binding_requires_node_ceremony_check_replay",
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
  return { root, releaseDirectory, manifest, documents, topology };
}

async function rewriteDescriptor(fixture, domain, mutate, { updateTopology = false } = {}) {
  const file = path.join(fixture.releaseDirectory, CVM_LAUNCH_DESCRIPTOR_FILES[domain]);
  const document = structuredClone(fixture.documents[domain]);
  mutate(document);
  fixture.documents[domain] = document;
  const manifestText = await readFile(
    path.join(fixture.releaseDirectory, "dnai-tee-image-release.json"),
  );
  const text = descriptorText(document, sha256(manifestText));
  await writeFile(file, text);
  if (updateTopology) {
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
}

test("generated boundary names all seven exact canonical descriptor files", () => {
  assert.deepEqual(
    CVM_RELEASE_DESCRIPTOR_GENERATED_FILES.slice(0, 7),
    CVM_LAUNCH_DOMAINS.map((domain) => CVM_LAUNCH_DESCRIPTOR_FILES[domain]),
  );
  assert.equal(
    CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    "dnai.cvm-release-descriptor-set-validation.v3",
  );
  assert.equal(
    CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN,
    "dnai-wikigen/cvm-release-descriptor-set-validation/v3\0",
  );
  assert.deepEqual(CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX.main_runtime_cvm, [
    "neko",
    "oracle",
    "delegate",
    "diligence-policy-init",
    "tinker-customer-authority-init",
    "arena-policy-init",
    "arena-worker",
    "anchor-writer-evidence",
    "deal-runtime",
    "compute-execution-worker",
    "collaboration-execution-worker",
    "review-operations",
    "mailbox-genesis",
    "tinker-account-genesis",
  ]);
  assert.equal(
    CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.launch_settings.initial_services
      .includes("mailbox-genesis"),
    false,
  );
  assert.equal(
    CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.launch_settings.initial_services
      .includes("tinker-account-genesis"),
    false,
  );
  assert.equal(
    CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.launch_settings
      .initially_disabled_profiles.includes("mailbox-genesis"),
    true,
  );
  assert.equal(
    CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.launch_settings
      .initially_disabled_profiles.includes("tinker-account-genesis"),
    true,
  );
});

test("validator accepts one complete seven-domain secret-free release set and binds raw hashes", async () => {
  const fixture = await buildFixture();
  try {
    const receipt = await validateCanonicalGeneratedCvmDescriptorSet({
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
    });
    assert.equal(receipt.schema, CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA);
    assert.equal(receipt.status, "validated_rendered_not_deployed");
    assert.equal(receipt.invariants.all_seven_generated_files_present, true);
    assert.equal(receipt.invariants.exact_clean_ci_image_digests, true);
    assert.equal(receipt.invariants.embedded_secret_values, false);
    assert.equal(
      receipt.image_manifest_sigstore_bundle_sha256,
      `sha256:${sha256('{"fixture":"attestation-bundle"}\n')}`,
    );
    assert.equal(
      receipt.tinker_account_binding_ceremony_receipt_sha256,
      fixture.topology.tinkerAccountBindingCeremonyReceipt
        .tinkerAccountBindingCeremonyReceiptSha256,
    );
    assert.equal(Object.keys(receipt.descriptor_sha256_by_domain).length, 7);
    assert.equal(new Set(Object.values(receipt.descriptor_sha256_by_domain)).size, 7);
    assert.equal(receipt.image_references.length, 5);
    assert.equal(JSON.stringify(receipt).includes("fixture requires"), false);
    assert.deepEqual(
      normalizeCvmReleaseDescriptorSetReceipt(receipt),
      structuredClone(receipt),
    );
    assert.match(
      cvmReleaseDescriptorSetReceiptSha256(receipt),
      /^sha256:[0-9a-f]{64}$/,
    );
    assert.throws(
      () => normalizeCvmReleaseDescriptorSetReceipt({
        ...structuredClone(receipt),
        schema: "dnai.cvm-release-descriptor-set-validation.v2",
      }),
      /receipt authority is invalid/,
    );
    assert.throws(
      () => normalizeCvmReleaseDescriptorSetReceipt({
        ...structuredClone(receipt),
        tinker_account_binding_ceremony_receipt_sha256:
          `sha256:${"0".repeat(64)}`,
      }),
      /Tinker account-binding ceremony receipt must be a nonzero canonical SHA-256 digest/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("validator rejects any missing canonical descriptor file", async () => {
  const fixture = await buildFixture();
  try {
    await unlink(path.join(fixture.releaseDirectory, "dnai-arena-qvl.phala.yaml"));
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /ENOENT/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("validator rejects raw descriptor hash drift against topology", async () => {
  const fixture = await buildFixture();
  try {
    await rewriteDescriptor(fixture, "main_runtime_cvm", (document) => {
      document["x-audit-marker"] = "hash-drift";
    });
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /topology does not bind the exact main_runtime_cvm descriptor/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("validator rejects account-binding receipt omission or topology substitution", async () => {
  const missing = await buildFixture();
  try {
    await unlink(path.join(
      missing.releaseDirectory,
      "tinker-account-binding-ceremony.receipt.json",
    ));
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: missing.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /ENOENT/,
    );
  } finally {
    await rm(missing.root, { recursive: true, force: true });
  }

  const substituted = await buildFixture();
  try {
    substituted.topology.tinkerAccountBindingCeremonyReceipt.sha256 =
      "f".repeat(64);
    await writeFile(
      path.join(substituted.releaseDirectory, "dnai-cvm-topology.json"),
      canonical(substituted.topology),
    );
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: substituted.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /does not bind the exact Tinker account-binding ceremony receipt/,
    );
  } finally {
    await rm(substituted.root, { recursive: true, force: true });
  }
});

test("validator rejects foreign or mutable service image authority", async () => {
  const fixture = await buildFixture();
  try {
    await rewriteDescriptor(fixture, "main_runtime_cvm", (document) => {
      document.services["arena-worker"].image = "ghcr.io/g-structure/dnai-wikigen/tinker-delegate:latest";
    }, { updateTopology: true });
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /arena-worker does not use the exact release image digest/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("validator rejects removal of Arena, Deal, Compute, Collaboration execution, or measured genesis services", async () => {
  for (const service of [
    "arena-worker",
    "deal-runtime",
    "compute-execution-worker",
    "collaboration-execution-worker",
    "mailbox-genesis",
    "tinker-account-genesis",
  ]) {
    const fixture = await buildFixture();
    try {
      await rewriteDescriptor(fixture, "main_runtime_cvm", (document) => {
        delete document.services[service];
      }, { updateTopology: true });
      await assert.rejects(
        validateCanonicalGeneratedCvmDescriptorSet({
          releaseDirectory: fixture.releaseDirectory,
          expectedReleaseSha: RELEASE_SHA,
        }),
        /service matrix is not exact/,
        service,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("validator rejects a raw secret value even when topology is rehashed", async () => {
  const fixture = await buildFixture();
  try {
    await rewriteDescriptor(fixture, "main_runtime_cvm", (document) => {
      document.services.delegate.environment.OPENROUTER_API_KEY = "sk-do-not-embed";
    }, { updateTopology: true });
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /embeds a nonempty secret-like value/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("validator rejects duplicate active-service late inputs outside the exact delegate environment mapping", async () => {
  const surfaces = [
    ["command", ["sh", "-c", "echo ${TINKER_ARENA_REGISTRY_ADDRESS:-}"]],
    ["entrypoint", ["sh", "${TINKER_ARENA_REGISTRY_ADDRESS:-}"]],
    ["healthcheck", { test: ["CMD", "${TINKER_ARENA_REGISTRY_ADDRESS:-}"] }],
    ["labels", { "audit-copy": "${TINKER_ARENA_REGISTRY_ADDRESS:-}" }],
  ];
  for (const [surface, value] of surfaces) {
    const fixture = await buildFixture();
    try {
      await rewriteDescriptor(fixture, "main_runtime_cvm", (document) => {
        document.services.delegate[surface] = value;
      }, { updateTopology: true });
      await assert.rejects(
        validateCanonicalGeneratedCvmDescriptorSet({
          releaseDirectory: fixture.releaseDirectory,
          expectedReleaseSha: RELEASE_SHA,
        }),
        /active-service late input TINKER_ARENA_REGISTRY_ADDRESS must occur exactly once/,
        surface,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("validator rejects an active-service late input whose environment mapping key is relocated", async () => {
  const fixture = await buildFixture();
  try {
    await rewriteDescriptor(fixture, "main_runtime_cvm", (document) => {
      const value = document.services.delegate.environment.TINKER_ARENA_REGISTRY_ADDRESS;
      delete document.services.delegate.environment.TINKER_ARENA_REGISTRY_ADDRESS;
      document.services.delegate.environment.RELOCATED_ARENA_REGISTRY_ADDRESS = value;
    }, { updateTopology: true });
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /mapping key equal to TINKER_ARENA_REGISTRY_ADDRESS/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("validator rejects a release manifest for any other source SHA", async () => {
  const fixture = await buildFixture();
  try {
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: "b".repeat(40),
      }),
      /manifest authority does not match/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("tracked-source reproduction requires byte-identical regeneration of all twelve files", async () => {
  const fixture = await buildFixture();
  try {
    const copyingRunner = async ({ outputDirectory, releaseDirectory }) => {
      for (const filename of CVM_RELEASE_DESCRIPTOR_GENERATED_FILES) {
        await writeFile(
          path.join(outputDirectory, filename),
          await readFile(path.join(releaseDirectory, filename)),
        );
      }
    };
    const receipt = await verifyExactTrackedSourceDescriptorReproduction({
      repositoryRoot: fixture.root,
      releaseDirectory: fixture.releaseDirectory,
      expectedReleaseSha: RELEASE_SHA,
      rendererRunner: copyingRunner,
    });
    assert.equal(receipt.status, "exact_tracked_source_reproduction");
    assert.equal(receipt.generated_file_count, 12);
    assert.equal(Object.keys(receipt.generated_file_sha256).length, 12);

    const foreignRoot = path.join(fixture.root, "foreign-repository");
    await mkdir(foreignRoot);
    await assert.rejects(
      verifyExactTrackedSourceDescriptorReproduction({
        repositoryRoot: foreignRoot,
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
        rendererRunner: copyingRunner,
      }),
      /repository's exact \.release directory/,
    );

    await assert.rejects(
      verifyExactTrackedSourceDescriptorReproduction({
        repositoryRoot: fixture.root,
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
        rendererRunner: async (context) => {
          await copyingRunner(context);
          await writeFile(
            path.join(context.outputDirectory, "dnai-main-runtime.phala.yaml"),
            "drifted reproduction\n",
          );
        },
      }),
      /dnai-main-runtime\.phala\.yaml is not the exact tracked-source reproduction/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("validator rejects group/world-writable generated evidence", async () => {
  const fixture = await buildFixture();
  try {
    const descriptor = path.join(
      fixture.releaseDirectory,
      CVM_LAUNCH_DESCRIPTOR_FILES.main_runtime_cvm,
    );
    await chmod(descriptor, 0o666);
    await assert.rejects(
      validateCanonicalGeneratedCvmDescriptorSet({
        releaseDirectory: fixture.releaseDirectory,
        expectedReleaseSha: RELEASE_SHA,
      }),
      /bounded nonempty regular file/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function buildSourceFixture() {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-descriptor-source-")));
  for (const relative of CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES) {
    const file = path.join(root, relative);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, `reviewed source ${relative}\n`);
  }
  return root;
}

function fakeGitRunner({ head = RELEASE_SHA, tracked = true, dirty = false } = {}) {
  return async (args) => {
    if (args[0] === "rev-parse") return `${head}\n`;
    if (args[0] === "ls-files") {
      if (!tracked) throw new Error("untracked");
      return `${CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES.join("\n")}\n`;
    }
    if (args[0] === "status") return dirty ? " M scripts/build-tee-image-release.mjs\n" : "";
    throw new Error("unexpected git command");
  };
}

test("tracked-source inspector binds clean tracked inputs to the exact release HEAD", async () => {
  const root = await buildSourceFixture();
  try {
    const receipt = await inspectTrackedDescriptorMaterializationSources({
      repositoryRoot: root,
      expectedReleaseSha: RELEASE_SHA,
      gitRunner: fakeGitRunner(),
    });
    assert.equal(receipt.ready, true);
    assert.equal(receipt.source_files.length, CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES.length);
    assert.deepEqual(receipt.blockers, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("tracked-source inspector fails closed for untracked, dirty, or wrong-HEAD inputs", async () => {
  const root = await buildSourceFixture();
  try {
    const untracked = await inspectTrackedDescriptorMaterializationSources({
      repositoryRoot: root,
      expectedReleaseSha: RELEASE_SHA,
      gitRunner: fakeGitRunner({ tracked: false }),
    });
    assert.equal(untracked.ready, false);
    assert.deepEqual(untracked.blockers, ["descriptor_materialization_source_untracked"]);

    const dirty = await inspectTrackedDescriptorMaterializationSources({
      repositoryRoot: root,
      expectedReleaseSha: RELEASE_SHA,
      gitRunner: fakeGitRunner({ dirty: true }),
    });
    assert.equal(dirty.ready, false);
    assert.deepEqual(dirty.blockers, ["descriptor_materialization_source_dirty"]);

    await assert.rejects(
      assertTrackedDescriptorMaterializationSources({
        repositoryRoot: root,
        expectedReleaseSha: RELEASE_SHA,
        gitRunner: fakeGitRunner({ head: "b".repeat(40) }),
      }),
      /git_head_does_not_equal_release_sha/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI help is diagnostic-only and malformed invocation stays blocked", async () => {
  let stdout = "";
  let stderr = "";
  assert.equal(await main(["--help"], {
    log: (value) => { stdout += value; },
    error: (value) => { stderr += value; },
  }), 0);
  assert.match(stdout, /Usage:/);
  assert.equal(stderr, "");

  stdout = "";
  assert.equal(await main(["check", "--repo-root", "/tmp"], {
    log: (value) => { stdout += value; },
    error: (value) => { stderr += value; },
  }), 2);
  assert.equal(stdout, "");
  assert.match(stderr, /"status":"blocked"/);
  assert.match(stderr, /"deployment_attempted":false/);
});
