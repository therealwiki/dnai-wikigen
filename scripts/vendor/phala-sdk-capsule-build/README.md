# Reproduce the reviewed SDK 0.4.0 capsule

This directory is a build recipe, not a runtime SDK dependency or launch
authority. The production loader imports only the exact pinned generated ESM
bytes. SDK-owned network, debug and event imports are replaced with the same
capability-restricting stubs used by the previous capsule.

The package lock fixes Cloud SDK 0.4.0, dstack SDK 0.5.8, esbuild 0.28.1, and the
previous contributing dependency versions. Only the 22 exported functions in
`capsule-entry.mjs` enter the bundle. `build-candidate.mjs` performs two compiler
invocations, requires identical outputs, checks the existing source-capability
boundary, collects the full contributing package licenses, and rejects outputs
whose SHA-256 differs from the reviewed capsule or notice pins.

Use the reviewed Node 24.9.0 binary. Run from this directory, with an empty local
HOME and private npm cache, no ambient credentials, and lifecycle scripts off:

```sh
mkdir -p -m 700 home npm-cache
env -i PATH=/opt/homebrew/Cellar/node/24.9.0/bin:/usr/bin:/bin \
  HOME="$PWD/home" NPM_CONFIG_USERCONFIG="$PWD/home/.npmrc" \
  NPM_CONFIG_GLOBALCONFIG=/dev/null NPM_CONFIG_CACHE="$PWD/npm-cache" \
  /opt/homebrew/Cellar/node/24.9.0/bin/node \
  /opt/homebrew/lib/node_modules/npm/bin/npm-cli.js \
  ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org

env -i PATH=/opt/homebrew/Cellar/node/24.9.0/bin:/usr/bin:/bin HOME="$PWD/home" \
  /opt/homebrew/Cellar/node/24.9.0/bin/node build-candidate.mjs
```

Generated files remain under the local `build/` directory and are never copied
automatically over active release artifacts. Dependency installation uses the
public npm registry; the compiler makes no Phala requests. All source/metadata
and output digests are recorded in `build/candidate-build.json`.

Local clean-install rebuilds reproduced the reviewed capsule before this recipe
was integrated. That is local reproducibility evidence, not independent
cross-host build attestation. Public registry signature and provenance evidence
is separately preserved under
`../npm/provenance/phala-cloud-0.4.0-dstack-0.5.8/`; runtime byte pinning is not
fresh online provenance verification.
