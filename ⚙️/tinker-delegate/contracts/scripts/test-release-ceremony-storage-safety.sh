#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
PATH_RESOLVER="$SCRIPT_DIR/release-ceremony-paths.sh"
INITIALIZER="$SCRIPT_DIR/initialize-release-ceremony-ledger.sh"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"
LEDGER_CLI="$ROOT_DIR/scripts/release-ceremony-ledger-cli.mjs"
DEPLOY_HELPER="$SCRIPT_DIR/deploy-base-sepolia.sh"
HELPERS=(
  "$SCRIPT_DIR/configure-challenge-registry-release.sh"
  "$SCRIPT_DIR/configure-compute-release.sh"
  "$SCRIPT_DIR/configure-diligence-release.sh"
  "$SCRIPT_DIR/configure-email-oracle-release.sh"
  "$SCRIPT_DIR/configure-execution-policy-anchor.sh"
  "$SCRIPT_DIR/configure-royalty-release.sh"
  "$SCRIPT_DIR/configure-tinker-release.sh"
)

for script in "$PATH_RESOLVER" "$INITIALIZER" "$POLICY_GUARD" "${HELPERS[@]}"; do
  bash -n "$script"
done
node --check "$LEDGER_CLI"

for helper in "${HELPERS[@]}"; do
  env_source_line="$(grep -n -m1 '^  \. "\$ROOT_DIR/\.env"$' "$helper" | cut -d: -f1)"
  resolver_line="$(grep -n -m1 '^operator_policy_resolve_release_ceremony_paths$' "$helper" | cut -d: -f1)"
  if [ -z "$env_source_line" ] || [ -z "$resolver_line" ] \
    || [ "$resolver_line" -le "$env_source_line" ]; then
    echo "$(basename "$helper") must source .env before resolving either ceremony path." >&2
    exit 1
  fi
  if [ "$(grep -Ec '^operator_policy_resolve_release_ceremony_paths$' "$helper")" -ne 1 ]; then
    echo "$(basename "$helper") must resolve ceremony paths exactly once." >&2
    exit 1
  fi
  if grep -Fq 'MANIFEST_PATH="${DEPLOYMENT_MANIFEST_PATH:-$ROOT_DIR/deployments/base-sepolia.json}"' "$helper"; then
    echo "$(basename "$helper") retains the historical pre-.env fallback." >&2
    exit 1
  fi
done

TEST_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dnai-ceremony-path-test.XXXXXX")"
cleanup() {
  rm -rf -- "$TEST_TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

fake_root="$TEST_TMP_DIR/repository"
mkdir -p "$fake_root/deployments"
touch "$fake_root/deployments/base-sepolia.json"
fresh_path="$TEST_TMP_DIR/operator/fresh-receipt.json"
ledger_path="$TEST_TMP_DIR/operator/ceremony-ledger.json"
evidence_root="$TEST_TMP_DIR/operator/evidence"
mkdir -p "$(dirname "$fresh_path")" "$evidence_root"
printf '%s\n' \
  "DEPLOYMENT_MANIFEST_PATH=$fresh_path" \
  "RELEASE_CEREMONY_LEDGER_PATH=$ledger_path" \
  "RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT=$evidence_root" \
  > "$fake_root/.env"

resolved="$(bash -c '
  set -euo pipefail
  ROOT_DIR="$1"
  set -a
  . "$ROOT_DIR/.env"
  set +a
  . "$2"
  operator_policy_resolve_release_ceremony_paths
  printf "%s\n%s\n" "$FRESH_DEPLOYMENT_MANIFEST_PATH" "$MANIFEST_PATH"
' _ "$fake_root" "$PATH_RESOLVER")"
if [ "$resolved" != "$(printf '%s\n%s' "$fresh_path" "$ledger_path")" ]; then
  echo "An env-only immutable receipt or ceremony-ledger path was not honored exactly." >&2
  exit 1
fi

# An existing historical ledger must not become an implicit source when .env
# provides only the working path.
printf '%s\n' \
  "RELEASE_CEREMONY_LEDGER_PATH=$ledger_path" \
  "RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT=$evidence_root" \
  > "$fake_root/.env"
if bash -c '
  set -euo pipefail
  ROOT_DIR="$1"
  set -a
  . "$ROOT_DIR/.env"
  set +a
  . "$2"
  operator_policy_resolve_release_ceremony_paths
' _ "$fake_root" "$PATH_RESOLVER" >/dev/null 2>&1; then
  echo "Missing env-only DEPLOYMENT_MANIFEST_PATH fell back to repository history." >&2
  exit 1
fi

historical_path="$fake_root/deployments/base-sepolia.json"
if DEPLOYMENT_MANIFEST_PATH="$historical_path" \
  RELEASE_CEREMONY_LEDGER_PATH="$ledger_path" \
  RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT="$evidence_root" \
  ROOT_DIR="$fake_root" \
  bash -c '. "$1"; operator_policy_resolve_release_ceremony_paths' \
    _ "$PATH_RESOLVER" >/dev/null 2>&1; then
  echo "The explicit historical deployments/base-sepolia.json path was accepted." >&2
  exit 1
fi
if DEPLOYMENT_MANIFEST_PATH="$fresh_path" \
  RELEASE_CEREMONY_LEDGER_PATH="$fresh_path" \
  RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT="$evidence_root" \
  ROOT_DIR="$fake_root" \
  bash -c '. "$1"; operator_policy_resolve_release_ceremony_paths' \
    _ "$PATH_RESOLVER" >/dev/null 2>&1; then
  echo "The immutable receipt was accepted as its own mutable ceremony ledger." >&2
  exit 1
fi

for boundary in \
  'release-ceremony-ledger-cli.mjs" commit' \
  '--source-manifest "$FRESH_DEPLOYMENT_MANIFEST_PATH"' \
  '--ledger "$RELEASE_CEREMONY_LEDGER_PATH"' \
  '--evidence-root "$RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT"' \
  '--lock-root "$RELEASE_CEREMONY_LOCK_ROOT"' \
  '--tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256"' \
  '--writer-id "$RELEASE_CEREMONY_LOCK_WRITER_ID"' \
  '--owner-token "$RELEASE_CEREMONY_LOCK_OWNER_TOKEN"'; do
  if ! grep -Fq -- "$boundary" "$POLICY_GUARD"; then
    echo "Shared ceremony-ledger commit boundary is missing: $boundary" >&2
    exit 1
  fi
done
if grep -Fq 'durable-json-write.mjs' "$POLICY_GUARD"; then
  echo "Mutating helpers still bypass the ceremony revision chain." >&2
  exit 1
fi
for boundary in \
  'operator_policy_acquire_release_ceremony_lock ceremony_ledger_initialization' \
  'release-ceremony-ledger-cli.mjs" initialize' \
  '--source-manifest "$FRESH_DEPLOYMENT_MANIFEST_PATH"' \
  '--ledger "$MANIFEST_PATH"' \
  '--tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256"' \
  'operator_policy_release_release_ceremony_lock'; do
  if ! grep -Fq -- "$boundary" "$INITIALIZER"; then
    echo "Ceremony-ledger initializer boundary is missing: $boundary" >&2
    exit 1
  fi
done
if ! grep -Fq 'jq -S \' "$DEPLOY_HELPER" \
  || ! grep -Fq 'durably_publish_json "$tmp_manifest" "$MANIFEST_PATH" create 0444' "$DEPLOY_HELPER"; then
  echo "Fresh deployment receipt must be canonical and immutable at first publication." >&2
  exit 1
fi

echo "Release ceremony storage safety checks passed."
