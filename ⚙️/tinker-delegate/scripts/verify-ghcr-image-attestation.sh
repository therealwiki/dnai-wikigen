#!/usr/bin/env bash
set -euo pipefail

REPO="G-structure/dnai-wikigen"
WORKFLOW="G-structure/dnai-wikigen/.github/workflows/build-tee-images.yml"
SOURCE_DIGEST=""
SOURCE_REF=""
OWNER=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/verify-ghcr-image-attestation.sh IMAGE_REF --source-digest GIT_SHA [options]

Verifies that a GHCR image digest has GitHub-signed provenance and SBOM
attestations from this repository's TEE image workflow before the image is
allowed into a Phala compose deployment.

Arguments:
  IMAGE_REF                     Fully qualified image ref or digest, for example:
                                ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:...

Options:
  --source-digest GIT_SHA       Required source commit SHA enforced by gh.
  --source-ref REF              Optional Git ref, for example refs/heads/main.
  --repo OWNER/REPO             GitHub repo that owns the attestation.
                                Default: G-structure/dnai-wikigen
  --signer-workflow WORKFLOW    Expected signer workflow identity.
                                Default: G-structure/dnai-wikigen/.github/workflows/build-tee-images.yml
  --owner OWNER                 Optional owner scope instead of --repo.

Requires:
  gh 2.92+ authenticated for the repo and GHCR package visibility.
USAGE
}

if [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

IMAGE_REF="$1"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-digest)
      SOURCE_DIGEST="${2:?--source-digest requires a value}"
      shift 2
      ;;
    --source-ref)
      SOURCE_REF="${2:?--source-ref requires a value}"
      shift 2
      ;;
    --repo)
      REPO="${2:?--repo requires a value}"
      OWNER=""
      shift 2
      ;;
    --signer-workflow)
      WORKFLOW="${2:?--signer-workflow requires a value}"
      shift 2
      ;;
    --owner)
      OWNER="${2:?--owner requires a value}"
      REPO=""
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$SOURCE_DIGEST" ]]; then
  echo "--source-digest is required" >&2
  usage >&2
  exit 2
fi

if [[ "$IMAGE_REF" != *@sha256:* ]]; then
  echo "IMAGE_REF must be digest-pinned with @sha256:" >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required" >&2
  exit 2
fi

scope_args=()
if [[ -n "$REPO" ]]; then
  scope_args+=(--repo "$REPO")
else
  scope_args+=(--owner "$OWNER")
fi

common_args=(
  "oci://$IMAGE_REF"
  "${scope_args[@]}"
  --bundle-from-oci
  --signer-workflow "$WORKFLOW"
  --source-digest "$SOURCE_DIGEST"
  --deny-self-hosted-runners
)
if [[ -n "$SOURCE_REF" ]]; then
  common_args+=(--source-ref "$SOURCE_REF")
fi

gh attestation verify "${common_args[@]}" \
  --predicate-type https://slsa.dev/provenance/v1 >/dev/null

gh attestation verify "${common_args[@]}" \
  --predicate-type https://spdx.dev/Document/v2.3 >/dev/null

cat <<EOF
{
  "image": "$IMAGE_REF",
  "repo": "${REPO:-$OWNER}",
  "signer_workflow": "$WORKFLOW",
  "source_digest": "$SOURCE_DIGEST",
  "source_ref": "$SOURCE_REF",
  "provenance_attestation": "verified",
  "sbom_attestation": "verified",
  "raw_secret_egress": false
}
EOF
