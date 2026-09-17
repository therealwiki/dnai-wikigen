# Public package provenance audit inputs

These are exact public inputs and recorded outputs from the successful
`observation-OCGkma` verification, started at `2026-09-16T20:32:14.193Z`, for
`@phala/cloud@0.4.0` and `@phala/dstack-sdk@0.5.8`.

**Truth boundary: reviewed source evidence, not runtime reverification.**
Packaging these files does not rerun npm, Sigstore, TUF, or Phala verification,
does not establish future revocation status, and does not authorize deployment.
Runtime enforcement is separate. No network calls occur during assembly.

## Included inputs

- `raw/`: exact npm metadata, registry keys, npm publish/SLSA bundles, signed TUF
  root rotations 13 through 15, signed timestamp/snapshot/targets, and trusted
  root HTTP response bytes. The observed 404 response for root 16 is retained
  as HTTP evidence; it is not a signed trust root.
- `trust-seed/`: the exact installed `@sigstore/tuf@3.1.1` seed JSON and its
  decoded root-12 bytes. Assembly checks the complete seed's SHA-256 against
  the hash recorded during the successful observation before decoding it.
- `tuf-final/`: final root, timestamp, snapshot, targets, and `trusted_root.json`
  bytes preserved from the freshly verified cache. The unrelated npm cache,
  private HOME directories, failed observations, and unverified cached targets
  are intentionally excluded.
- Recorded verifier/runtime identity, network requests, TUF results, acquisition
  hashes, successful package evidence, and offline negative-control results.
- `helpers/`: byte-preserved verification scripts. The public verifier's bytes
  are checked against the captured `verification-inputs.json` hash. The negative
  helper was executed after that initial observation; its bytes are covered by
  this directory's file manifest, not retroactively by the earlier helper hash.

The two package tarballs are maintained separately under `scripts/vendor/npm/`;
their exact hashes and sizes are in `acquisition.json` and the package evidence.
The raw signed attestation subjects bind their PURLs and SHA-512 digests.

## Trust update and recorded result

The installed seed root was version 12 and expired in 2025. The successful
verification freshly followed and verified signed rotations `12 → 13 → 14 → 15`
and the current timestamp/snapshot/targets chain. Timestamp version 785 expires
`2026-09-23T19:23:52Z`. This is a historical verification observation, not a claim
that its timestamp will remain current.

The actual contacted hosts were only `registry.npmjs.org` and
`tuf-repo-cdn.sigstore.dev`. Both origins were explicitly allowed; ambient
credentials, authorization/cookie headers, non-HTTPS requests, other origins,
and non-GET methods were rejected. Do not replace this with a registry-only
provenance claim.

The two registry signatures passed both independent Node crypto and pacote
verification. Both npm publish and both SLSA bundles verified; the exact saved
bundles were reverified separately from pacote's refetch. Offline controls then
accepted four unchanged bundles and rejected 12 deliberate mutations without
network requests.

## File manifest and reproducibility

`file-manifest.json` uses sorted keys, sorted relative paths, two-space JSON,
and a final newline. It covers every regular file below this directory except
itself, including this README and the assembly helper, with exact SHA-256 and
byte length. Its own digest must be pinned outside this self-contained list.
All packaged entries must be regular, non-symlink, single-link files.

`assemble-audit-inputs.mjs` copies already-observed public artifacts only,
checks stable reads and the captured helper/seed hashes, and produces the
deterministic manifest. It refuses to replace existing files with different
bytes. Its operational source paths are deliberately preserved:

```text
/Users/wikios/Projects/dnai-wikigen/outputs/release-tools/phala-sdk-0.4.0/registry/observation-OCGkma
/Users/wikios/Projects/dnai-wikigen/outputs/release-tools/phala-sdk-0.4.0/registry/verify-public-registry.mjs
/Users/wikios/Projects/dnai-wikigen/outputs/release-tools/phala-sdk-0.4.0/registry/verify-negative-controls.mjs
/opt/homebrew/lib/node_modules/npm/node_modules/@sigstore/tuf/seeds.json
```

The archived verification helpers also preserve their original npm installation
path and observation-directory assumptions. They are not drop-in runtime
scripts and should not be silently rewritten while claiming their old hash.
To repeat the live verification, copy their exact bytes into a separate writable
scratch directory with the original sibling `observation-*` layout and review
the installed npm/runtime dependency paths first. Running the public verifier
would make new public network calls and create a new observation; the archived
evidence is not a substitute for that new result.

The signed provenance statements name Cloud SDK source commit
`13d2915e27be7014b9fc9dc18fe1ae4485bf2283` in
`https://github.com/Phala-Network/phala-cloud` and dstack source commit
`bed5c61904a5ed1d6c481a14a303f4c057befea7` in
`https://github.com/Dstack-TEE/dstack`. Their presence here does not establish a
separate source review or a reproducible runtime-capsule build.
