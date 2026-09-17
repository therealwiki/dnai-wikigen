// Offline assembly of already-observed public evidence. This is not a package,
// Sigstore, TUF, Phala, or runtime-authority verifier.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const destination = path.dirname(fileURLToPath(import.meta.url));
const observation = '/Users/wikios/Projects/dnai-wikigen/outputs/release-tools/phala-sdk-0.4.0/registry/observation-OCGkma';
const originalHelpers = path.dirname(observation);
const installedSeed = '/opt/homebrew/lib/node_modules/npm/node_modules/@sigstore/tuf/seeds.json';
const manifestName = 'file-manifest.json';
const sha256 = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const sorted = value => Array.isArray(value) ? value.map(sorted)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const canonical = value => Buffer.from(`${JSON.stringify(sorted(value), null, 2)}\n`);

function regularBytes(file) {
  const before = fs.lstatSync(file, { bigint: true });
  assert(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n,
    `Not a regular non-symlink single-link file: ${file}`);
  assert(before.size > 0n && before.size <= 4n * 1024n * 1024n, `File size outside audit bound: ${file}`);
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const finalPath = fs.lstatSync(file, { bigint: true });
    for (const field of ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) {
      assert(before[field] === opened[field] && opened[field] === after[field]
        && after[field] === finalPath[field], `Input changed during read: ${file}`);
    }
    assert.equal(bytes.length, Number(before.size));
    return bytes;
  } finally { fs.closeSync(descriptor); }
}

function place(relative, bytes) {
  assert(!relative.startsWith('/') && !relative.split('/').includes('..'));
  const target = path.join(destination, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
  if (fs.existsSync(target)) {
    assert(regularBytes(target).equals(bytes), `Refusing to replace different existing evidence: ${relative}`);
  } else {
    fs.writeFileSync(target, bytes, { flag: 'wx', mode: 0o644 });
  }
}

function copy(source, relative) { place(relative, regularBytes(source)); }

const inputs = JSON.parse(regularBytes(path.join(observation, 'verification-inputs.json')));
const capturedHelper = regularBytes(path.join(originalHelpers, 'verify-public-registry.mjs'));
assert.equal(sha256(capturedHelper), inputs.helper.sha256,
  'Public verifier no longer matches the helper captured by the successful observation');
const seed = regularBytes(installedSeed);
assert.equal(sha256(seed), inputs.installed_tuf_seed_sha256,
  'Installed authentic Sigstore seed no longer matches the captured observation');
const seedRoot = Buffer.from(JSON.parse(seed)['https://tuf-repo-cdn.sigstore.dev']['root.json'], 'base64');
assert.equal(JSON.parse(seedRoot).signed.version, 12);
place('trust-seed/sigstore-tuf-3.1.1-seeds.json', seed);
place('trust-seed/root-12.json', seedRoot);
place('helpers/verify-public-registry.mjs', capturedHelper);
copy(path.join(originalHelpers, 'verify-negative-controls.mjs'), 'helpers/verify-negative-controls.mjs');

for (const filename of [
  'verification-inputs.json', 'network-requests.json', 'tuf-verification-observation.json',
  'negative-control-results.json', 'upstream-registry-evidence.json', 'acquisition.json',
]) {
  copy(path.join(observation, filename), filename);
}
for (const filename of fs.readdirSync(path.join(observation, 'raw')).sort()) {
  copy(path.join(observation, 'raw', filename), `raw/${filename}`);
}
const finalTuf = path.join(observation, 'tuf-cache', 'tuf-repo-cdn.sigstore.dev');
for (const filename of ['root.json', 'timestamp.json', 'snapshot.json', 'targets.json']) {
  copy(path.join(finalTuf, filename), `tuf-final/${filename}`);
}
copy(path.join(finalTuf, 'targets', 'trusted_root.json'), 'tuf-final/targets/trusted_root.json');

function listFiles(directory, prefix = '') {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (relative === manifestName) continue;
    assert(!entry.isSymbolicLink(), `Symlink in packaged evidence: ${relative}`);
    if (entry.isDirectory()) files.push(...listFiles(path.join(directory, entry.name), relative));
    else {
      assert(entry.isFile(), `Non-regular packaged evidence: ${relative}`);
      files.push(relative);
    }
  }
  return files.sort();
}
const files = listFiles(destination).map(relative => {
  const bytes = regularBytes(path.join(destination, relative));
  return { path: relative, sha256: sha256(bytes), byte_length: bytes.length };
});
const evidence = JSON.parse(regularBytes(path.join(destination, 'upstream-registry-evidence.json')));
const manifest = canonical({
  schema: 'dnai.phala-sdk-upstream-audit-input-manifest.v1',
  truth_status: 'reviewed_source_evidence_not_runtime_reverification',
  source_observation: 'observation-OCGkma',
  observed_at: evidence.observed_at,
  coverage: 'all_regular_files_recursively_below_this_directory_except_file-manifest.json',
  network_during_assembly: false,
  files,
});
place(manifestName, manifest);
// Re-read the complete result so symlinks, byte drift, or unmanifested files
// cannot be hidden by a successful copy/serialization operation.
assert.deepEqual(listFiles(destination), files.map(file => file.path));
for (const file of files) {
  const bytes = regularBytes(path.join(destination, file.path));
  assert.equal(bytes.length, file.byte_length);
  assert.equal(sha256(bytes), file.sha256);
}
console.log(JSON.stringify({
  manifest: path.join(destination, manifestName),
  sha256: sha256(manifest), byte_length: manifest.length,
  file_count: files.length, evidence_bytes: files.reduce((sum, file) => sum + file.byte_length, 0),
  assembly_network_calls: 0,
}));
