import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const manifestPath = path.join(
  repositoryRoot,
  "web/src/assets/pitch/asset-provenance.json",
);
const SOURCE_SPECIFIERS = Object.freeze({
  "attested-network":
    "../../outputs/wikigen-pitch-assets/attested-network.png",
  "private-reward-oracle":
    "../../outputs/wikigen-pitch-assets/private-reward-oracle.png",
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function gitBlobOid(bytes) {
  return createHash("sha1")
    .update(`blob ${bytes.length}\0`, "utf8")
    .update(bytes)
    .digest("hex");
}

function exactKeys(value, expected, label) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), label);
  assert.deepEqual(Object.keys(value), expected, label);
}

function inspectPng(bytes, label) {
  assert.equal(bytes.subarray(0, 8).toString("hex"), "89504e470d0a1a0a", label);
  const chunks = [];
  let offset = 8;
  while (offset < bytes.length) {
    assert.ok(offset + 12 <= bytes.length, `${label}: truncated PNG chunk`);
    const size = bytes.readUInt32BE(offset);
    const type = bytes.subarray(offset + 4, offset + 8).toString("ascii");
    const end = offset + 12 + size;
    assert.ok(end <= bytes.length, `${label}: oversized PNG chunk`);
    chunks.push({ type, size });
    offset = end;
  }
  assert.equal(offset, bytes.length, `${label}: trailing PNG bytes`);
  assert.equal(chunks[0]?.type, "IHDR", `${label}: IHDR must be first`);
  assert.equal(chunks.at(-1)?.type, "IEND", `${label}: IEND must be last`);
  const originChunks = chunks.filter(({ type }) => type === "caBX");
  assert.deepEqual(originChunks, [{ type: "caBX", size: 24_922 }], label);
  return {
    width: bytes.readUInt32BE(16),
    height: bytes.readUInt32BE(20),
  };
}

function inspectWebp(bytes, label) {
  assert.equal(bytes.subarray(0, 4).toString("ascii"), "RIFF", label);
  assert.equal(bytes.subarray(8, 12).toString("ascii"), "WEBP", label);
  assert.equal(bytes.readUInt32LE(4) + 8, bytes.length, `${label}: RIFF size`);
  const chunks = [];
  let offset = 12;
  while (offset < bytes.length) {
    assert.ok(offset + 8 <= bytes.length, `${label}: truncated WebP chunk`);
    const type = bytes.subarray(offset, offset + 4).toString("ascii");
    const size = bytes.readUInt32LE(offset + 4);
    const payloadOffset = offset + 8;
    const payloadEnd = payloadOffset + size;
    assert.ok(payloadEnd <= bytes.length, `${label}: oversized WebP chunk`);
    chunks.push({ type, size, payloadOffset });
    offset = payloadEnd + (size % 2);
  }
  assert.equal(offset, bytes.length, `${label}: trailing WebP bytes`);
  assert.equal(chunks.length, 1, `${label}: metadata or extra WebP feature`);
  assert.equal(chunks[0].type, "VP8 ", `${label}: expected lossy VP8 only`);
  const payloadOffset = chunks[0].payloadOffset;
  assert.ok(chunks[0].size >= 10, `${label}: truncated VP8 frame`);
  assert.equal(
    bytes.subarray(payloadOffset + 3, payloadOffset + 6).toString("hex"),
    "9d012a",
    `${label}: VP8 keyframe marker`,
  );
  return {
    width: bytes.readUInt16LE(payloadOffset + 6) & 0x3fff,
    height: bytes.readUInt16LE(payloadOffset + 8) & 0x3fff,
  };
}

const EXPECTED_ASSETS = Object.freeze([
  Object.freeze({
    name: "attested-network",
    width: 1672,
    height: 941,
    source: Object.freeze({
      path: "outputs/wikigen-pitch-assets/attested-network.png",
      git_blob: "44bb90203aebc374b02173553db8417dbe5d3ddb",
      bytes: 2_020_938,
      sha256: "f975a6d1d33bd7ee50a0f376746397fe670f9c04cf8be98e04424a94897bbddd",
      origin_metadata: "embedded_c2pa_jumbf_present_not_independently_verified",
    }),
    output: Object.freeze({
      path: "web/src/assets/pitch/attested-network.webp",
      bytes: 170_256,
      sha256: "74988af25153a37684555bb6713782ce248c4de8270121792c4ad9eaf183ebd1",
      embedded_metadata: "none",
    }),
  }),
  Object.freeze({
    name: "private-reward-oracle",
    width: 1672,
    height: 941,
    source: Object.freeze({
      path: "outputs/wikigen-pitch-assets/private-reward-oracle.png",
      git_blob: "1ee640620bc8e343cc2f363a00d934c2978faf33",
      bytes: 2_145_155,
      sha256: "7297a78244aff235a500b9658c0f984d7115a77a4a58b25bacecc05126394f94",
      origin_metadata: "embedded_c2pa_jumbf_present_not_independently_verified",
    }),
    output: Object.freeze({
      path: "web/src/assets/pitch/private-reward-oracle.webp",
      bytes: 199_296,
      sha256: "14aa2ed2e42f7f38b95316f06a4bc0c50e136e883811bcbf1277ce94f3645fc9",
      embedded_metadata: "none",
    }),
  }),
]);

test("tracked pitch WebPs match their explicit source and derivative provenance", async () => {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  exactKeys(
    manifest,
    ["schema", "truth_status", "encoder", "assets", "rights_status"],
    "manifest",
  );
  assert.equal(manifest.schema, "dnai.web-pitch-asset-provenance.v1");
  assert.equal(
    manifest.truth_status,
    "tracked_png_origin_and_deterministic_webp_recipe_not_asset_rights_or_c2pa_chain_verification",
  );
  exactKeys(
    manifest.encoder,
    ["name", "version", "libsharpyuv_version", "local_binary_sha256", "arguments"],
    "encoder",
  );
  assert.deepEqual(manifest.encoder, {
    name: "cwebp",
    version: "1.6.0",
    libsharpyuv_version: "0.4.2",
    local_binary_sha256:
      "beed71767112f3374e2178b75384fac6e0d448932ea11b5cafda2793ecfb2eaf",
    arguments: ["-quiet", "-q", "84", "-m", "4"],
  });
  assert.deepEqual(manifest.assets, EXPECTED_ASSETS);
  for (const asset of manifest.assets) {
    exactKeys(asset, ["name", "width", "height", "source", "output"], asset.name);
    exactKeys(
      asset.source,
      ["path", "git_blob", "bytes", "sha256", "origin_metadata"],
      `${asset.name}: source`,
    );
    exactKeys(
      asset.output,
      ["path", "bytes", "sha256", "embedded_metadata"],
      `${asset.name}: output`,
    );
    const sourceSpecifier = SOURCE_SPECIFIERS[asset.name];
    assert.equal(typeof sourceSpecifier, "string", `${asset.name}: source mapping`);
    const sourcePath = path.resolve(scriptDirectory, sourceSpecifier);
    assert.equal(
      path.relative(repositoryRoot, sourcePath).split(path.sep).join("/"),
      asset.source.path,
      `${asset.name}: source path binding`,
    );
    const sourceBytes = await readFile(sourcePath);
    assert.equal(sourceBytes.length, asset.source.bytes, asset.source.path);
    assert.equal(sha256(sourceBytes), asset.source.sha256, asset.source.path);
    assert.equal(gitBlobOid(sourceBytes), asset.source.git_blob, asset.source.path);
    assert.deepEqual(
      inspectPng(sourceBytes, asset.source.path),
      { width: asset.width, height: asset.height },
    );

    const outputBytes = await readFile(path.join(repositoryRoot, asset.output.path));
    assert.equal(outputBytes.length, asset.output.bytes, asset.output.path);
    assert.equal(sha256(outputBytes), asset.output.sha256, asset.output.path);
    assert.deepEqual(
      inspectWebp(outputBytes, asset.output.path),
      { width: asset.width, height: asset.height },
    );
  }
  assert.equal(
    manifest.rights_status,
    "repository_license_intent_is_agplv3_but_asset_specific_rights_are_not_independently_confirmed",
  );
});
