import assert from 'node:assert/strict';
import { createHash, createVerify } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const npmRoot = '/opt/homebrew/lib/node_modules/npm';
const registry = 'https://registry.npmjs.org';
const tufOrigin = 'https://tuf-repo-cdn.sigstore.dev';
const keyid = 'SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U';
const packages = [
  ['@phala/cloud', '0.4.0', 'phala-cloud-0.4.0.tgz'],
  ['@phala/dstack-sdk', '0.5.8', 'phala-dstack-sdk-0.5.8.tgz'],
];
const expectedPredicates = [
  'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
  'https://slsa.dev/provenance/v1',
];
const sorted = value => Array.isArray(value) ? value.map(sorted)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]))
    : value;
const json = value => `${JSON.stringify(sorted(value), null, 2)}\n`;
const hash = (algorithm, bytes, encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const save = (file, bytes) => fs.writeFileSync(file, bytes, { flag: 'wx', mode: 0o600 });

// Never inherit npm, proxy, credential, NODE_OPTIONS, or user configuration.
// A fresh private HOME/cache is made for each real observation, not reused.
if (process.argv[2] !== '--isolated-child') {
  fs.chmodSync(here, 0o700);
  const run = fs.mkdtempSync(path.join(here, 'observation-'));
  for (const directory of ['home', 'npm-cache', 'tuf-cache', 'raw']) {
    fs.mkdirSync(path.join(run, directory), { mode: 0o700 });
  }
  console.log(JSON.stringify({ observation_directory: run }));
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--isolated-child'], {
    cwd: run,
    env: {
      PATH: '/usr/bin:/bin',
      HOME: path.join(run, 'home'),
      NPM_CONFIG_CACHE: path.join(run, 'npm-cache'),
      TUF_CACHE: path.join(run, 'tuf-cache'),
      OBSERVATION_DIRECTORY: run,
    },
    stdio: 'inherit',
    timeout: 180_000,
  });
  if (child.error) throw child.error;
  process.exit(child.status ?? 1);
}

process.umask(0o077);
// CoreFoundation inserts this non-credential variable when starting Node on
// macOS even with an explicit empty environment; it is not needed here.
delete process.env.__CF_USER_TEXT_ENCODING;
const run = process.env.OBSERVATION_DIRECTORY;
assert.equal(path.dirname(run), here);
assert.equal(fs.realpathSync(run), run);
assert.deepEqual(Object.keys(process.env).sort(), [
  'HOME', 'NPM_CONFIG_CACHE', 'OBSERVATION_DIRECTORY', 'PATH', 'TUF_CACHE',
]);
assert.deepEqual(fs.readdirSync(process.env.HOME), []);
assert.deepEqual(fs.readdirSync(process.env.NPM_CONFIG_CACHE), []);
assert.deepEqual(fs.readdirSync(process.env.TUF_CACHE), []);

const requests = [];
function guardRequest(input, options = {}) {
  const url = typeof input === 'string' || input instanceof URL
    ? new URL(input) : new URL(`${input.protocol ?? 'https:'}//${input.hostname ?? input.host}${input.path ?? '/'}`);
  assert.equal(url.protocol, 'https:', 'Non-HTTPS network request rejected');
  assert([registry, tufOrigin].includes(url.origin), 'Unexpected network origin rejected');
  assert.equal(url.username + url.password, '', 'URL credentials rejected');
  const headers = { ...(input?.headers ?? {}), ...(options?.headers ?? {}) };
  assert(!Object.keys(headers).some(name => /^(authorization|proxy-authorization|cookie)$/i.test(name)),
    'Credential-bearing request header rejected');
  const record = { method: options?.method ?? input?.method ?? 'GET', url: url.href };
  assert.equal(record.method, 'GET', 'Only read-only GET requests are allowed');
  requests.push(record);
  return record;
}
const originalHttpsRequest = https.request;
https.request = function (input, options, callback) {
  const record = guardRequest(input, typeof options === 'object' ? options : {});
  const sequence = requests.length;
  const request = originalHttpsRequest.apply(this, arguments);
  request.on('response', response => {
    record.status = response.statusCode;
    if (new URL(record.url).origin !== tufOrigin) return;
    const chunks = [];
    let size = 0;
    response.on('data', chunk => {
      size += chunk.length;
      if (size > 4 * 1024 * 1024) request.destroy(new Error('TUF evidence response exceeded bound'));
      else chunks.push(chunk);
    });
    response.on('end', () => {
      const bytes = Buffer.concat(chunks);
      const filename = `${sequence}-${encodeURIComponent(new URL(record.url).pathname)}.response`;
      save(path.join(run, 'raw', filename), bytes);
      record.response_file = `raw/${filename}`;
      record.response_sha256 = `sha256:${hash('sha256', bytes)}`;
      record.response_byte_length = bytes.length;
    });
  });
  return request;
};
http.request = () => { throw new Error('Plain HTTP request rejected'); };

async function publicBytes(url, maximum = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      method: 'GET', headers: { accept: 'application/json', 'user-agent': 'dnai-public-package-verifier/1' },
    }, response => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`Public registry request failed with HTTP ${response.statusCode}`));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > maximum) request.destroy(new Error('Public registry response exceeded bound'));
        else chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => resolve(Buffer.concat(chunks)));
    });
    request.setTimeout(15_000, () => request.destroy(new Error('Public registry request timed out')));
    request.on('error', reject);
    request.end();
  });
}

try {
  const observedAt = new Date().toISOString();
  const keyBytes = await publicBytes(`${registry}/-/npm/v1/keys`);
  save(path.join(run, 'raw', 'registry-keys.json'), keyBytes);
  const keys = JSON.parse(keyBytes).keys;
  assert(Array.isArray(keys));
  const selected = keys.filter(key => key.keyid === keyid);
  assert.equal(selected.length, 1, 'Expected one reviewed npm registry signing key');
  const key = selected[0];
  assert.equal(key.keytype, 'ecdsa-sha2-nistp256');
  const publicKeys = keys.map(item => ({
    ...item, pemkey: `-----BEGIN PUBLIC KEY-----\n${item.key}\n-----END PUBLIC KEY-----`,
  }));
  const entries = [];
  for (const [name, version, filename] of packages) {
    const safeName = filename.replace('.tgz', '');
    const metadataBytes = await publicBytes(`${registry}/${name.replace('/', '%2f')}/${version}`);
    save(path.join(run, 'raw', `${safeName}.metadata.json`), metadataBytes);
    const manifest = JSON.parse(metadataBytes);
    assert.equal(manifest.name, name);
    assert.equal(manifest.version, version);
    const tarballUrl = `${registry}/${name}/-/${name.split('/')[1]}-${version}.tgz`;
    assert.equal(manifest.dist.tarball, tarballUrl);
    assert.match(manifest.dist.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
    assert.match(manifest.dist.shasum, /^[0-9a-f]{40}$/);
    assert.equal(manifest.dist.signatures.length, 1);
    const signature = manifest.dist.signatures[0];
    assert.equal(signature.keyid, keyid);
    const message = `${name}@${version}:${manifest.dist.integrity}`;
    const verify = createVerify('SHA256');
    verify.update(message);
    verify.end();
    assert(verify.verify(publicKeys.find(item => item.keyid === keyid).pemkey, signature.sig, 'base64'),
      'Independent registry ECDSA signature verification failed');
    const tarball = await publicBytes(tarballUrl, 1024 * 1024);
    assert.equal(`sha512-${hash('sha512', tarball, 'base64')}`, manifest.dist.integrity);
    assert.equal(hash('sha1', tarball), manifest.dist.shasum);
    const tarballPath = path.join(run, filename);
    save(tarballPath, tarball);
    const attestationsUrl = manifest.dist.attestations?.url;
    assert.equal(new URL(attestationsUrl).origin, registry);
    const attestationBytes = await publicBytes(attestationsUrl);
    save(path.join(run, 'raw', `${safeName}.attestations.json`), attestationBytes);
    const attestations = JSON.parse(attestationBytes).attestations;
    assert.equal(attestations.length, 2);
    assert.deepEqual(attestations.map(item => item.predicateType), expectedPredicates);
    for (const attestation of attestations) {
      const statement = JSON.parse(Buffer.from(attestation.bundle.dsseEnvelope.payload, 'base64'));
      assert.equal(statement.predicateType, attestation.predicateType);
      assert.equal(statement.subject.length, 1);
      assert.equal(statement.subject[0].name, `pkg:npm/${name.replace('@', '%40')}@${version}`);
      assert.equal(statement.subject[0].digest.sha512, hash('sha512', tarball));
    }
    entries.push({ name, version, tarballPath, manifest, attestations, tarball });
    console.log(JSON.stringify({ acquired: `${name}@${version}`, tarball_path: tarballPath,
      byte_length: tarball.length, tarball_sha256: `sha256:${hash('sha256', tarball)}`,
      independent_registry_signature_and_integrity_verified: true,
      attestations_verified: false }));
  }
  save(path.join(run, 'acquisition.json'), json(entries.map(({ name, version, tarballPath, tarball }) => ({
    name, version, tarball_path: tarballPath, tarball_sha256: `sha256:${hash('sha256', tarball)}`,
    byte_length: tarball.length,
  }))));

  const require = createRequire(path.join(npmRoot, 'package.json'));
  const pacote = require('pacote');
  const sigstore = require('sigstore');
  const tuf = require('@sigstore/tuf');
  // Bootstrap from the official installed trust seed and verify every signed
  // root rotation and current timestamp/snapshot/targets update using TUF.
  // The exact public response bytes are captured above, without credentials.
  await tuf.getTrustedRoot({ cachePath: process.env.TUF_CACHE, forceCache: false,
    timeout: 15_000, retry: { retries: 0 } });
  const options = {
    registry,
    cache: process.env.NPM_CONFIG_CACHE,
    tufCache: process.env.TUF_CACHE,
    verifySignatures: true,
    verifyAttestations: true,
    fullMetadata: true,
    '//registry.npmjs.org/:_keys': publicKeys,
    fetchRetries: 0,
    fetchTimeout: 15_000,
  };
  const results = [];
  for (const { name, version, manifest, attestations, tarball } of entries) {
    const verified = await pacote.manifest(`${name}@${version}`, options);
    assert.equal(verified._integrity, manifest.dist.integrity);
    assert.deepEqual(verified._signatures, manifest.dist.signatures);
    assert.deepEqual(verified._attestations, manifest.dist.attestations);
    // Verify the exact saved attestation bytes too, not only pacote's refetch.
    for (const { bundle } of attestations) {
      const bundleKeyId = bundle.dsseEnvelope.signatures[0].keyid;
      await sigstore.verify(bundle, {
        tufCachePath: process.env.TUF_CACHE,
        tufForceCache: true,
        keySelector: bundleKeyId
          ? requestedKey => {
            assert.equal(requestedKey, bundleKeyId);
            return publicKeys.find(item => item.keyid === bundleKeyId)?.pemkey;
          }
          : undefined,
      });
    }
    results.push({
      name, version, byte_length: tarball.length,
      tarball_url: manifest.dist.tarball,
      tarball_sha256: `sha256:${hash('sha256', tarball)}`,
      npm_dist_integrity_sha512: manifest.dist.integrity,
      npm_dist_shasum_sha1: manifest.dist.shasum,
      registry_signature: { ...manifest.dist.signatures[0], verified: true },
      attestations_url: manifest.dist.attestations.url,
      attestation_count: attestations.length,
      predicate_types: attestations.map(item => item.predicateType),
      attestations_verified: true,
    });
    console.log(JSON.stringify({ verified: `${name}@${version}`, registry_signature: true,
      npm_publish_attestation: true, slsa_provenance_attestation: true }));
  }
  const evidence = {
    schema: 'dnai.phala-sdk-upstream-registry-evidence.v1',
    observed_at: observedAt,
    truth_status: 'fresh_public_npm_registry_https_bytes_signature_and_attestation_verification_not_future_revocation_or_reproducible_bundle_build_authority',
    registry: {
      origin: registry,
      public_key_endpoint: `${registry}/-/npm/v1/keys`,
      request_authentication: 'none_public_registry',
      signing_key_expires_at: key.expires,
      signing_key_id: key.keyid,
      signing_key_type: key.keytype,
    },
    verification: {
      ambient_registry_tokens_used: false,
      attestation_verifier: 'pacote_verifyAttestations_with_fresh_sigstore_TUF_update_and_force_cache',
      empty_home_and_private_npm_cache: true,
      external_network_hosts: [...new Set(requests.map(item => new URL(item.url).hostname))].sort(),
      npm_cli_version: require('./package.json').version,
      pacote_version: require('pacote/package.json').version,
      registry_signature_message: '${name}@${version}:${dist.integrity}',
      registry_signatures_verified_twice: 'pacote_and_independent_node_crypto_ecdsa_sha256',
      sigstore_js_version: require('sigstore/package.json').version,
      sigstore_tuf_seed_version: `@sigstore/tuf@${require('@sigstore/tuf/package.json').version}`,
      tarballs_refetched_and_byte_hashed: true,
    },
    packages: results,
  };
  save(path.join(run, 'upstream-registry-evidence.json'), json(evidence));
  save(path.join(run, 'network-requests.json'), json(requests));
  save(path.join(run, 'verification-inputs.json'), json({
    node: { realpath: fs.realpathSync(process.execPath), version: process.version,
      sha256: `sha256:${hash('sha256', fs.readFileSync(process.execPath))}` },
    helper: { path: fileURLToPath(import.meta.url), sha256: `sha256:${hash('sha256', fs.readFileSync(fileURLToPath(import.meta.url)))}` },
    installed_tuf_seed_sha256: `sha256:${hash('sha256', fs.readFileSync(require.resolve('@sigstore/tuf/seeds.json')))}`,
    trust_limit: 'Bootstraps from the official locally installed npm Sigstore TUF seed and cryptographically verifies fresh signed root rotations, timestamp, snapshot, targets and trust-root bytes. Does not establish future revocation state or reproducible bundle-build authority.',
  }));
  const tufMetadata = {};
  for (const filename of ['root.json', 'timestamp.json', 'snapshot.json', 'targets.json']) {
    const bytes = fs.readFileSync(path.join(process.env.TUF_CACHE, 'tuf-repo-cdn.sigstore.dev', filename));
    const signed = JSON.parse(bytes).signed;
    tufMetadata[filename] = { sha256: `sha256:${hash('sha256', bytes)}`,
      byte_length: bytes.length, version: signed.version, expires: signed.expires };
  }
  const trustedRootBytes = fs.readFileSync(path.join(process.env.TUF_CACHE,
    'tuf-repo-cdn.sigstore.dev', 'targets', 'trusted_root.json'));
  save(path.join(run, 'tuf-verification-observation.json'), json({
    observed_at: new Date().toISOString(), metadata: tufMetadata,
    trusted_root: { sha256: `sha256:${hash('sha256', trustedRootBytes)}`, byte_length: trustedRootBytes.length },
    origin: tufOrigin, signed_update_verified_by: `@sigstore/tuf@${require('@sigstore/tuf/package.json').version}`,
  }));
  console.log(JSON.stringify({ status: 'VERIFIED', evidence: path.join(run, 'upstream-registry-evidence.json') }));
} catch (error) {
  save(path.join(run, 'failure.json'), json({ observed_at: new Date().toISOString(),
    status: 'FAILED', name: error.name, code: error.code ?? null, message: error.message,
    network_requests: requests }));
  console.error(error);
  process.exitCode = 1;
}
