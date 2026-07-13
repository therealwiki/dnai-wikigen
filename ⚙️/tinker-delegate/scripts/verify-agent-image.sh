#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${1:-dnai-tinker-delegate-agent-extra:local}"

echo "== Building tinker-delegate image with optional Tinker SDK =="
docker build -t "$IMAGE_TAG" "$ROOT_DIR"

echo "== Verifying optional Tinker SDK inside image =="
docker run --rm -i "$IMAGE_TAG" python - <<'PY'
import json

import tinker  # noqa: F401
import tinker_delegate.api as api

print(json.dumps({
    "image_check": "tinker-delegate-agent-extra",
    "agent_stack_available": api._agent_stack_available(),
    "raw_secret_egress": False,
}, sort_keys=True))
if not api._agent_stack_available():
    raise SystemExit("agent stack unavailable")
PY
