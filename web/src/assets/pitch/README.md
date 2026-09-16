# Pitch illustration derivatives

These two WebP files are repository-tracked delivery derivatives of the tracked
PNG masters under `outputs/wikigen-pitch-assets/`. The PNGs remain the origin
records because they contain C2PA/JUMBF metadata; that metadata is present but
has not been independently chain-verified in this repository. WebP conversion
strips it, so `asset-provenance.json` binds each source and derivative by path,
Git blob, dimensions, byte length, SHA-256, and encoder recipe.

Regenerate from the repository root with `cwebp 1.6.0`:

```sh
cwebp -quiet -q 84 -m 4 \
  outputs/wikigen-pitch-assets/attested-network.png \
  -o web/src/assets/pitch/attested-network.webp
cwebp -quiet -q 84 -m 4 \
  outputs/wikigen-pitch-assets/private-reward-oracle.png \
  -o web/src/assets/pitch/private-reward-oracle.webp
```

The root README states the repository's AGPLv3 licensing intent. No separate
asset-specific rights grant has been independently confirmed, so the manifest
does not claim one.
