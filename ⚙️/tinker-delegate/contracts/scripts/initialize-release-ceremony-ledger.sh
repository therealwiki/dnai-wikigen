#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/release-ceremony-paths.sh"
operator_policy_resolve_release_ceremony_paths

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; ceremony-ledger authority is never inferred." >&2
    exit 1
  fi
}

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

for required in git jq node; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required." >&2
    exit 1
  fi
done

for name in \
  RELEASE_SHA \
  DEPLOYMENT_INTENT_PATH \
  DEPLOYMENT_INTENT_SHA256 \
  DEPLOYMENT_MANIFEST_PATH \
  RELEASE_CEREMONY_LEDGER_PATH \
  RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT \
  RELEASE_CEREMONY_LOCK_ROOT \
  TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256; do
  require_env "$name"
done
operator_policy_require_absolute_regular_file DEPLOYMENT_INTENT_PATH
operator_policy_require_sha256 DEPLOYMENT_INTENT_SHA256
operator_policy_require_sha256 TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256
if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || [[ "$RELEASE_SHA" =~ ^0{40}$ ]]; then
  echo "RELEASE_SHA must be the nonzero lowercase 40-hex reviewed Git commit." >&2
  exit 1
fi
operator_policy_assert_current_source

if ! intent_receipt="$(node "$ROOT_DIR/scripts/operator-policy-packet.mjs" \
  check-intent --in "$DEPLOYMENT_INTENT_PATH")"; then
  echo "Deployment-intent validation failed; ceremony ledger was not initialized." >&2
  exit 1
fi
if [ "${#intent_receipt}" -gt 8192 ] || ! jq -e \
  --arg intentSha "$DEPLOYMENT_INTENT_SHA256" \
  --arg releaseSha "$RELEASE_SHA" '
    .schema == "dnai.deployment-intent-validation-receipt.v6"
    and .status == "valid"
    and .deploymentIntentSha256 == $intentSha
    and .releaseSha == $releaseSha
    and .chainId == 84532
  ' <<<"$intent_receipt" >/dev/null; then
  echo "Deployment-intent receipt does not match this exact release." >&2
  exit 1
fi
if ! reviewer_acceptance_sha256="$(jq -er '
  .release.reviewerAuthorityGenesisAcceptanceSha256
  | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
  ' "$DEPLOYMENT_INTENT_PATH")" \
  || [ "$reviewer_acceptance_sha256" = "sha256:$(printf '0%.0s' {1..64})" ]; then
  echo "Deployment intent omits the nonzero reviewer-genesis acceptance digest." >&2
  exit 1
fi

operator_policy_acquire_release_ceremony_lock ceremony_ledger_initialization
node "$ROOT_DIR/scripts/release-ceremony-ledger-cli.mjs" initialize \
  --repository-root "$ROOT_DIR" \
  --source-manifest "$FRESH_DEPLOYMENT_MANIFEST_PATH" \
  --ledger "$MANIFEST_PATH" \
  --evidence-root "$RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT" \
  --lock-root "$RELEASE_CEREMONY_LOCK_ROOT" \
  --release-sha "$RELEASE_SHA" \
  --deployment-intent-sha256 "$DEPLOYMENT_INTENT_SHA256" \
  --reviewer-genesis-acceptance-sha256 "$reviewer_acceptance_sha256" \
  --tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256" \
  --writer-id ceremony_ledger_initialization \
  --owner-token "$RELEASE_CEREMONY_LOCK_OWNER_TOKEN"
operator_policy_release_release_ceremony_lock

echo "Initialized the external mode-0600 ceremony ledger exactly once; the immutable mode-0444 fresh receipt was not rewritten."
