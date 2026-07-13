#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -eq 0 ]]; then
  cat <<'USAGE'
Usage:
  scripts/verify-cvm-attestation.sh API_URL --compose docker-compose.all.phala.yaml \
    --expected-compose-hash HASH --app-id APP_ID --os-image-hash OS_IMAGE_HASH \
    --require-image-digest sha256:...

This is an operator wrapper around:
  uv run python -m tinker_delegate.main verify-cvm-attestation

By default it rejects local attestation, mutable tag-only images, compose-hash
mismatches, app/OS-image mismatches, stale client fetches, and report-data/key
mismatches. Use --allow-local-attestation only for local development.
USAGE
  exit 0
fi

cd "$(dirname "$0")/.."
exec uv run python -m tinker_delegate.main verify-cvm-attestation "$@"
