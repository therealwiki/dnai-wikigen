#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image_tag=${IMAGE_TAG:-dnai-attestation-qvl:local}

exec docker build \
  --pull=false \
  --build-arg SOURCE_DATE_EPOCH=1735689600 \
  --tag "$image_tag" \
  "$project_dir"
