#!/usr/bin/env bash
set -euo pipefail

echo "Direct compose additions are intentionally unavailable." >&2
echo "A compose change requires a fresh halted TinkerAccountEncumbrance deployment" >&2
echo "and both phases of contracts/scripts/configure-tinker-release.sh, separated" >&2
echo "by the enforced two-day release-policy timelock." >&2
exit 1
