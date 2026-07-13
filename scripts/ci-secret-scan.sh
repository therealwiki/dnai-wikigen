#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exclude_paths=(
  ":(exclude)📄/**"
  ":(exclude)🔬/**"
  ":(exclude)outputs/**"
  ":(exclude)**/uv.lock"
  ":(exclude)**/.venv/**"
  ":(exclude)**/out/**"
  ":(exclude)**/broadcast/**"
)

patterns=(
  'phak_[A-Za-z0-9_-]{16,}'
  'tml-[A-Za-z0-9_-]{16,}'
  'gh[pousr]_[A-Za-z0-9_]{20,}'
  'sk-[A-Za-z0-9_-]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{20,}'
  '-----BEGIN ((RSA|EC|OPENSSH) )?PRIVATE KEY-----'
  'private[_-]?key[[:space:]]*[:=][[:space:]]*["'\'']?0x[0-9a-fA-F]{64}'
  '(card_number|cardNumber|cvc|cvv)[[:space:]]*[:=][[:space:]]*["'\'']?[0-9][0-9 -]{10,}'
)

fixture_allowlist='tml-secret|4242424242424242|cvc=123|secret-token'

found=0
for pattern in "${patterns[@]}"; do
  matches="$(git grep -nEI -e "$pattern" -- . "${exclude_paths[@]}" | grep -Ev "$fixture_allowlist" || true)"
  if [ -n "$matches" ]; then
    echo "Potential secret pattern matched: $pattern" >&2
    echo "$matches" >&2
    found=1
  fi
done

if [ "$found" -ne 0 ]; then
  echo "Secret scan failed. Remove or quarantine the matched material." >&2
  exit 1
fi

echo "Secret scan passed."
