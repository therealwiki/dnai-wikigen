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
const observation = fs.realpathSync(process.argv[2]);
assert.equal(path.dirname(observation), here);
if (process.argv[3] !== '--isolated-child') {
  const home = fs.mkdtempSync(path.join(observation, 'negative-controls-home-'));
  const child = spawnSync(process.execPath,
    [fileURLToPath(import.meta.url), observation, '--isolated-child'], {
      cwd: observation, env: { PATH: '/usr/bin:/bin', HOME: home },
      stdio: 'inherit', timeout: 60_000,
    });
  if (child.error) throw child.error;
  process.exit(child.status ?? 1);
}
delete process.env.__CF_USER_TEXT_ENCODING;
assert.deepEqual(Object.keys(process.env).sort(), ['HOME', 'PATH']);
assert.deepEqual(fs.readdirSync(process.env.HOME), []);
process.umask(0o077);
let networkAttempts = 0;
const rejectNetwork = () => { networkAttempts += 1; throw new Error('Negative controls are strictly offline'); };
http.request = rejectNetwork;
https.request = rejectNetwork;
globalThis.fetch = rejectNetwork;
const require = createRequire('/opt/homebrew/lib/node_modules/npm/package.json');
const sigstore = require('sigstore');
const digest = (algorithm, bytes, encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const keys = JSON.parse(fs.readFileSync(path.join(observation, 'raw', 'registry-keys.json'))).keys;
const results = [];
const verifications = [];
for (const [name, version, stem] of [
  ['@phala/cloud', '0.4.0', 'phala-cloud-0.4.0'],
  ['@phala/dstack-sdk', '0.5.8', 'phala-dstack-sdk-0.5.8'],
]) {
  const manifest = JSON.parse(fs.readFileSync(path.join(observation, 'raw', `${stem}.metadata.json`)));
  const tarball = fs.readFileSync(path.join(observation, `${stem}.tgz`));
  assert.equal(`sha512-${digest('sha512', tarball, 'base64')}`, manifest.dist.integrity);
  const changedTarball = Buffer.from(tarball);
  changedTarball[changedTarball.length - 1] ^= 1;
  assert.notEqual(`sha512-${digest('sha512', changedTarball, 'base64')}`, manifest.dist.integrity);
  results.push({ package: `${name}@${version}`, mutation: 'one_tarball_byte_changed', rejected: true });
  const key = keys.find(item => item.keyid === manifest.dist.signatures[0].keyid);
  assert(key);
  const pemkey = `-----BEGIN PUBLIC KEY-----\n${key.key}\n-----END PUBLIC KEY-----`;
  const registryVerify = message => {
    const verifier = createVerify('SHA256');
    verifier.update(message);
    verifier.end();
    return verifier.verify(pemkey, manifest.dist.signatures[0].sig, 'base64');
  };
  assert.equal(registryVerify(`${name}@${version}:${manifest.dist.integrity}`), true);
  assert.equal(registryVerify(`${name}@0.0.0-invalid:${manifest.dist.integrity}`), false);
  results.push({ package: `${name}@${version}`, mutation: 'registry_signature_bound_version_changed', rejected: true });
  const attestations = JSON.parse(fs.readFileSync(path.join(observation, 'raw', `${stem}.attestations.json`))).attestations;
  for (const { predicateType, bundle } of attestations) {
    const bundleKeyId = bundle.dsseEnvelope.signatures[0].keyid;
    const options = {
      tufCachePath: path.join(observation, 'tuf-cache'), tufForceCache: true,
      keySelector: bundleKeyId ? requested => {
        assert.equal(requested, bundleKeyId);
        const selected = keys.find(item => item.keyid === requested);
        assert(selected);
        return `-----BEGIN PUBLIC KEY-----\n${selected.key}\n-----END PUBLIC KEY-----`;
      } : undefined,
    };
    await sigstore.verify(bundle, options);
    verifications.push({ package: `${name}@${version}`, predicate_type: predicateType, original_verified: true });
    for (const mutation of ['dsse_signature_byte_changed', 'signed_subject_digest_changed']) {
      const changed = structuredClone(bundle);
      if (mutation === 'dsse_signature_byte_changed') {
        const signature = Buffer.from(changed.dsseEnvelope.signatures[0].sig, 'base64');
        signature[signature.length - 1] ^= 1;
        changed.dsseEnvelope.signatures[0].sig = signature.toString('base64');
      } else {
        const statement = JSON.parse(Buffer.from(changed.dsseEnvelope.payload, 'base64'));
        statement.subject[0].digest.sha512 = '0'.repeat(128);
        changed.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString('base64');
      }
      let rejection;
      try { await sigstore.verify(changed, options); }
      catch (error) { rejection = { name: error.name, code: error.code ?? null, message: error.message }; }
      assert(rejection, `Tampered ${predicateType} bundle was accepted`);
      results.push({ package: `${name}@${version}`, predicate_type: predicateType, mutation,
        rejected: true, rejection });
    }
  }
}
assert.equal(networkAttempts, 0);
const report = {
  observed_at: new Date().toISOString(), status: 'PASS', network_attempts: networkAttempts,
  positive_attestation_controls: verifications, negative_controls: results,
  scope: 'Cryptographic tamper rejection for freshly downloaded package bytes and exact saved npm publish/SLSA bundles; not Phala compatibility or deployment authority.',
};
const reportPath = path.join(observation, 'negative-control-results.json');
fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
console.log(JSON.stringify({ status: report.status, negative_controls_passed: results.length,
  original_attestation_controls_passed: verifications.length, network_attempts: networkAttempts,
  report: reportPath }));
