#!/bin/bash -p

DNAI_RELEASE_STARTUP_FLAGS=$-
set +x
case "$DNAI_RELEASE_STARTUP_FLAGS" in
  *x*) echo "Shell xtrace is forbidden for release wrappers because it can disclose environment values." >&2; exit 1 ;;
  *p*) ;;
  *) echo "This release wrapper must be executed directly or with /bin/bash -p; plain bash invocation is unsupported." >&2; exit 1 ;;
esac
if [ "${BASH_SOURCE[0]}" != "$0" ]; then echo "Release wrappers may not be sourced; execute this file directly or with /bin/bash -p." >&2; exit 1; fi
DNAI_RELEASE_STARTUP_HOOK_FOUND=false
DNAI_RELEASE_EXPORTED_NAMES="$(builtin compgen -e)" || { echo "Exported environment names could not be enumerated safely." >&2; exit 1; }
while IFS= read -r DNAI_RELEASE_STARTUP_ENV_NAME; do
  case "$DNAI_RELEASE_STARTUP_ENV_NAME" in BASH_ENV|ENV|SHELLOPTS|BASHOPTS|BASH_XTRACEFD|PS4|CDPATH|GLOBIGNORE|LD_*|DYLD_*|BASH_FUNC_*) DNAI_RELEASE_STARTUP_HOOK_FOUND=true; break ;; esac
done <<< "$DNAI_RELEASE_EXPORTED_NAMES"
if [ "$DNAI_RELEASE_STARTUP_HOOK_FOUND" = "true" ]; then echo "Shell startup, imported-function, and native-loader control variables are forbidden for release wrappers." >&2; exit 1; fi
unset DNAI_RELEASE_EXPORTED_NAMES DNAI_RELEASE_STARTUP_ENV_NAME DNAI_RELEASE_STARTUP_HOOK_FOUND
unset BASH_ENV ENV BASH_XTRACEFD PS4 CDPATH GLOBIGNORE 2>/dev/null || true
export -n SHELLOPTS BASHOPTS
set -euo pipefail

case "${BASH_SOURCE[0]}" in */*) DNAI_RELEASE_WRAPPER_DIR="${BASH_SOURCE[0]%/*}" ;; *) DNAI_RELEASE_WRAPPER_DIR=. ;; esac
ROOT_DIR="$(builtin cd -P -- "$DNAI_RELEASE_WRAPPER_DIR/../../../.." && builtin pwd -P)" || { echo "Could not resolve the canonical repository root with Bash builtins." >&2; exit 1; }
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
DNAI_KEYSTORE_ENVIRONMENT_HELPER="$CONTRACTS_DIR/scripts/keystore-deployment-environment.sh"
DNAI_KEYSTORE_HELPER_PARENT="${DNAI_KEYSTORE_ENVIRONMENT_HELPER%/*}"
DNAI_KEYSTORE_HELPER_CANONICAL_PARENT="$(builtin cd -P -- "$DNAI_KEYSTORE_HELPER_PARENT" && builtin pwd -P)" || { echo "Could not resolve the canonical keystore environment helper directory." >&2; exit 1; }
DNAI_KEYSTORE_HELPER_CANONICAL_PATH="$DNAI_KEYSTORE_HELPER_CANONICAL_PARENT/${DNAI_KEYSTORE_ENVIRONMENT_HELPER##*/}"
if [ "$DNAI_KEYSTORE_HELPER_CANONICAL_PATH" != "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" ] || [ ! -f "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" ] || [ -L "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" ] || [ ! -r "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" ]; then echo "The keystore environment helper must be the canonical readable non-symlink regular file." >&2; exit 1; fi
DNAI_KEYSTORE_HELPER_METADATA="$(/usr/bin/stat -f '%u:%l:%Lp' -- "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" 2>/dev/null || true)"; if [[ ! "$DNAI_KEYSTORE_HELPER_METADATA" =~ ^[0-9]+:[0-9]+:[0-7]+$ ]]; then DNAI_KEYSTORE_HELPER_METADATA="$(/usr/bin/stat -c '%u:%h:%a' -- "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" 2>/dev/null || true)"; fi
if [[ ! "$DNAI_KEYSTORE_HELPER_METADATA" =~ ^[0-9]+:[0-9]+:[0-7]+$ ]]; then echo "The keystore environment helper metadata could not be verified." >&2; exit 1; fi
IFS=: read -r DNAI_KEYSTORE_HELPER_OWNER DNAI_KEYSTORE_HELPER_LINKS DNAI_KEYSTORE_HELPER_MODE <<< "$DNAI_KEYSTORE_HELPER_METADATA"
if [ "$DNAI_KEYSTORE_HELPER_OWNER" != "$EUID" ] || [ "$DNAI_KEYSTORE_HELPER_LINKS" != "1" ] || (( (8#$DNAI_KEYSTORE_HELPER_MODE & 0022) != 0 )); then echo "The keystore environment helper must be owned by the invoking user, have one link, and not be group/world writable." >&2; exit 1; fi
DNAI_KEYSTORE_HELPER_PARENT_METADATA="$(/usr/bin/stat -f '%u:%Lp' -- "$DNAI_KEYSTORE_HELPER_PARENT" 2>/dev/null || true)"; if [[ ! "$DNAI_KEYSTORE_HELPER_PARENT_METADATA" =~ ^[0-9]+:[0-7]+$ ]]; then DNAI_KEYSTORE_HELPER_PARENT_METADATA="$(/usr/bin/stat -c '%u:%a' -- "$DNAI_KEYSTORE_HELPER_PARENT" 2>/dev/null || true)"; fi
IFS=: read -r DNAI_KEYSTORE_HELPER_PARENT_OWNER DNAI_KEYSTORE_HELPER_PARENT_MODE <<< "$DNAI_KEYSTORE_HELPER_PARENT_METADATA"
if [ ! -d "$DNAI_KEYSTORE_HELPER_PARENT" ] || [ -L "$DNAI_KEYSTORE_HELPER_PARENT" ] || [ "$DNAI_KEYSTORE_HELPER_PARENT_OWNER" != "$EUID" ] || [[ ! "$DNAI_KEYSTORE_HELPER_PARENT_MODE" =~ ^[0-7]+$ ]] || (( (8#$DNAI_KEYSTORE_HELPER_PARENT_MODE & 0022) != 0 )); then echo "The keystore helper directory must be canonical, invoking-user-owned, and not group/world writable." >&2; exit 1; fi
if [ ! -x /usr/bin/perl ]; then echo "The fixed /usr/bin/perl runtime required for helper descriptor identity checks is unavailable." >&2; exit 1; fi
exec 9< "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" || { echo "The keystore environment helper could not be opened safely." >&2; exit 1; }
DNAI_KEYSTORE_HELPER_PATH_IDENTITY="$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/perl -T -e 'my @s = lstat($ARGV[0]); scalar(@s) or exit 1; print join q{:}, @s[0,1,2,3,4];' "$DNAI_KEYSTORE_ENVIRONMENT_HELPER")" || { exec 9<&-; echo "The helper path identity could not be verified." >&2; exit 1; }
DNAI_KEYSTORE_HELPER_FD_IDENTITY="$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/perl -T -e 'my @s = stat(STDIN); scalar(@s) or exit 1; print join q{:}, @s[0,1,2,3,4];' <&9)" || { exec 9<&-; echo "The helper descriptor identity could not be verified." >&2; exit 1; }
if [ -L "$DNAI_KEYSTORE_ENVIRONMENT_HELPER" ] || [ "$DNAI_KEYSTORE_HELPER_PATH_IDENTITY" != "$DNAI_KEYSTORE_HELPER_FD_IDENTITY" ]; then exec 9<&-; echo "The keystore environment helper changed between custody validation and open." >&2; exit 1; fi
# shellcheck disable=SC1091
. /dev/fd/9
exec 9<&-
CHAIN_ID=84532
ACCOUNT=dev
MAX_SAFE_JSON_INTEGER=9007199254740991
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-execution-policy-anchor-release-manifest.jq"
ANCHOR_MANIFEST_TEMP_PATH=""

dnai_load_keystore_deployment_dotenv "$ROOT_DIR/.env"
dnai_finalize_keystore_deployment_environment BROADCAST

# DEPLOYMENT_MANIFEST_PATH and RELEASE_CEREMONY_LEDGER_PATH are resolved only
# after .env; repository history is never a ceremony fallback.
# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/release-ceremony-paths.sh"
operator_policy_resolve_release_ceremony_paths

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

cleanup_execution_policy_anchor_release() {
  if [ -n "${ANCHOR_MANIFEST_TEMP_PATH:-}" ]; then
    rm -f -- "$ANCHOR_MANIFEST_TEMP_PATH"
    ANCHOR_MANIFEST_TEMP_PATH=""
  fi
  cleanup_operator_policy_projection
}

trap cleanup_execution_policy_anchor_release EXIT
trap 'cleanup_execution_policy_anchor_release; exit 1' HUP INT TERM

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; policy-anchor release identity is never inferred." >&2
    exit 1
  fi
}

normalize_hex() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

validate_address() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]] || [ "$(normalize_hex "$value")" = "$ZERO_ADDRESS" ]; then
    echo "$name must be a nonzero Ethereum address." >&2
    exit 1
  fi
}

validate_bytes32() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] || [ "$(normalize_hex "$value")" = "$ZERO_BYTES32" ]; then
    echo "$name must be a nonzero bytes32 value." >&2
    exit 1
  fi
}

validate_bool() {
  local name="$1"
  local value="$2"
  if [ "$value" != "true" ] && [ "$value" != "false" ]; then
    echo "$name must be true or false." >&2
    exit 1
  fi
}

validate_sha256_digest() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [ "$value" = "sha256:$(printf '0%.0s' {1..64})" ]; then
    echo "$name must be a nonzero lowercase sha256:<64-hex> digest." >&2
    exit 1
  fi
}

validate_safe_json_uint() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ ]]; then
    echo "$name must be a canonical unsigned base-10 integer." >&2
    exit 1
  fi
  if [ "${#value}" -gt "${#MAX_SAFE_JSON_INTEGER}" ] \
    || { [ "${#value}" -eq "${#MAX_SAFE_JSON_INTEGER}" ] && [[ "$value" > "$MAX_SAFE_JSON_INTEGER" ]]; }; then
    echo "$name exceeds the exact JSON integer range." >&2
    exit 1
  fi
}

canonical_receipt_uint() {
  local name="$1"
  local value="$2"
  local canonical
  value="$(printf '%s\n' "$value" | awk 'NF { print $1; exit }')"
  if [[ "$value" =~ ^0x[0-9a-fA-F]+$ ]]; then
    canonical="$(cast to-dec "$value")"
  else
    canonical="$value"
  fi
  validate_safe_json_uint "$name" "$canonical"
  printf '%s' "$canonical"
}

deployment_ledger_blob() {
  git hash-object --no-filters "$MANIFEST_PATH"
}

validate_existing_deployment_ledger() {
  if [ ! -f "$MANIFEST_PATH" ] || [ -L "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be an existing non-symlink regular file at $MANIFEST_PATH." >&2
    exit 1
  fi
  if [ ! -r "$MANIFEST_PATH" ] || [ ! -w "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be readable and writable." >&2
    exit 1
  fi
  if ! jq -e \
    --arg anchor "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
    --arg runtime "$EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH" \
    --arg source "$RELEASE_SHA" \
    '
      type == "object"
      and .network.chainId == 84532
      and ((.contracts.executionPolicyAnchor.address // "") | ascii_downcase) == ($anchor | ascii_downcase)
      and ((.contracts.executionPolicyAnchor.runtimeCodeHash // "") | ascii_downcase) == ($runtime | ascii_downcase)
      and .contracts.executionPolicyAnchor.sourceCommit == $source
      and .freshDeployment.contractSuite.sourceCommit == $source
      and ((.executionPolicyAnchorReleaseHistory // []) | type) == "array"
    ' "$MANIFEST_PATH" >/dev/null; then
    echo "Deployment ledger address, runtime, or source does not match this execution-policy release." >&2
    exit 1
  fi
}

check_release_provenance() {
  require_env RELEASE_SHA
  if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || [ "$RELEASE_SHA" != "$(git -C "$ROOT_DIR" rev-parse HEAD)" ]; then
    echo "RELEASE_SHA must equal the exact lowercase checked-out commit." >&2
    exit 1
  fi
  if [ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]; then
    echo "Refusing policy-anchor governance broadcast from a dirty source tree." >&2
    exit 1
  fi
}

for required in forge cast git jq node; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required." >&2
    exit 1
  fi
done

for name in \
  BASE_SEPOLIA_RPC_URL \
  RELEASE_SHA \
  DEPLOYMENT_OPERATOR \
  EXECUTION_POLICY_ANCHOR_ADDRESS \
  EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH \
  EXECUTION_POLICY_ANCHOR_WRITER \
  EXECUTION_POLICY_RELEASE_CORE_PATH \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  EXECUTION_POLICY_ANCHOR_RELEASE_PHASE; do
  require_env "$name"
done

validate_bool BROADCAST "$BROADCAST"
if [[ ! "$EXECUTION_POLICY_ANCHOR_RELEASE_PHASE" =~ ^[12]$ ]]; then
  echo "EXECUTION_POLICY_ANCHOR_RELEASE_PHASE must be exactly 1 or 2." >&2
  exit 1
fi
for name in DEPLOYMENT_OPERATOR EXECUTION_POLICY_ANCHOR_ADDRESS EXECUTION_POLICY_ANCHOR_WRITER; do
  validate_address "$name" "${!name}"
done
validate_bytes32 EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH "$EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH"
validate_sha256_digest OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"
validate_sha256_digest OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256"
if [ "$(normalize_hex "$EXECUTION_POLICY_ANCHOR_WRITER")" = "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ] \
  || [ "$(normalize_hex "$EXECUTION_POLICY_ANCHOR_WRITER")" = "$(normalize_hex "$EXECUTION_POLICY_ANCHOR_ADDRESS")" ]; then
  echo "The anchor writer must be separate from governance and the anchor contract." >&2
  exit 1
fi


operator_policy_project_and_validate
operator_policy_assert_public_env postDeployEnv EXECUTION_POLICY_ANCHOR_WRITER

if [[ "$EXECUTION_POLICY_RELEASE_CORE_PATH" != /* ]]; then
  echo "EXECUTION_POLICY_RELEASE_CORE_PATH must be an absolute path." >&2
  exit 1
fi
derived_release_commitment="$(node "$ROOT_DIR/scripts/execution-policy-release-core-cli.mjs" \
  --artifact "$EXECUTION_POLICY_RELEASE_CORE_PATH" \
  --release-sha "$RELEASE_SHA" \
  --operator "$DEPLOYMENT_OPERATOR" \
  --anchor "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  --anchor-code-hash "$EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH" \
  --writer "$EXECUTION_POLICY_ANCHOR_WRITER")"
validate_bytes32 derived_release_commitment "$derived_release_commitment"
if [ -n "${EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT:-}" ] \
  && [ "$(normalize_hex "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT")" != "$(normalize_hex "$derived_release_commitment")" ]; then
  echo "EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT does not match the reviewed release-core artifact." >&2
  exit 1
fi
export EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT="$derived_release_commitment"
operator_policy_assert_public_env \
  postDeployEnv \
  EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT \
  TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT

ledger_blob_before_broadcast=""
if [ "$BROADCAST" = "true" ]; then
  # The evidence target is part of the authorization boundary. Validate it
  # before any irreversible write, then prove it remained unchanged before
  # replacing it with the append-only release evidence below.
  validate_existing_deployment_ledger
  ledger_blob_before_broadcast="$(deployment_ledger_blob)"
fi
if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  echo "Policy-anchor governance is restricted to the Foundry keystore account named dev." >&2
  exit 1
fi
if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
  echo "Foundry keystore account dev was not found. Use /cast-wallet first." >&2
  exit 1
fi

live_chain_id="$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$live_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing policy-anchor release: RPC chainId $live_chain_id is not Base Sepolia $CHAIN_ID." >&2
  exit 1
fi
live_code_hash="$(cast codehash "$EXECUTION_POLICY_ANCHOR_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_hex "$live_code_hash")" != "$(normalize_hex "$EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH")" ]; then
  echo "ExecutionPolicyAnchor runtime code does not match the reviewed release hash." >&2
  exit 1
fi
live_owner="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'owner()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_hex "$live_owner")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ]; then
  echo "DEPLOYMENT_OPERATOR is not the live ExecutionPolicyAnchor owner." >&2
  exit 1
fi
if [ "$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'paused()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")" != "true" ]; then
  echo "ExecutionPolicyAnchor must remain paused throughout writer admission." >&2
  exit 1
fi
if [ "$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalSequence()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')" != "0" ] \
  || [ "$(normalize_hex "$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalHead()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")")" != "$ZERO_BYTES32" ]; then
  echo "Refusing to configure an anchor that already contains decisions." >&2
  exit 1
fi

if [ "$BROADCAST" = "true" ]; then
  check_release_provenance
  if [ "$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")" = "0" ]; then
    echo "DEPLOYMENT_OPERATOR has no Base Sepolia ETH for governance gas." >&2
    exit 1
  fi
fi

echo "== ExecutionPolicyAnchor release phase $EXECUTION_POLICY_ANCHOR_RELEASE_PHASE =="
echo "Chain ID:          $live_chain_id"
echo "Keystore account:  dev"
echo "Operator:          $DEPLOYMENT_OPERATOR"
echo "Anchor:            $EXECUTION_POLICY_ANCHOR_ADDRESS"
echo "Writer:            $EXECUTION_POLICY_ANCHOR_WRITER"
echo "Release commitment: $EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT"
echo "Broadcast:         $BROADCAST"

cd "$CONTRACTS_DIR"
forge build --sizes
forge test --match-path test/ConfigureExecutionPolicyAnchor.t.sol

echo
echo "== Dry run =="
forge script script/ConfigureExecutionPolicyAnchor.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

if [ "$BROADCAST" != "true" ]; then
  echo "Dry run complete; no chain state changed."
  exit 0
fi

operator_policy_acquire_release_ceremony_lock execution_policy_anchor_release

check_release_provenance
validate_existing_deployment_ledger
ledger_blob_before_broadcast="$(deployment_ledger_blob)"
unlocked_signer="$(cast wallet address --account dev)"
if [ "$(normalize_hex "$unlocked_signer")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ]; then
  echo "The unlocked dev keystore does not match DEPLOYMENT_OPERATOR." >&2
  exit 1
fi

echo
echo "== Broadcast exact timelocked phase =="
forge script script/ConfigureExecutionPolicyAnchor.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --account dev \
  --broadcast \
  --slow

writer="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writer()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
release="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerReleaseCommitment()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_writer="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriter()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_release="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriterReleaseCommitment()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_at="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriterActivatesAt()(uint64)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
frozen="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerRotationsFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
paused="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'paused()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
global_sequence="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalSequence()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
global_head="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalHead()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
validate_safe_json_uint pending_at "$pending_at"
validate_safe_json_uint global_sequence "$global_sequence"

if [ "$EXECUTION_POLICY_ANCHOR_RELEASE_PHASE" = "1" ]; then
  if [ "$(normalize_hex "$writer")" != "$ZERO_ADDRESS" ] \
    || [ "$(normalize_hex "$release")" != "$ZERO_BYTES32" ] \
    || [ "$(normalize_hex "$pending_writer")" != "$(normalize_hex "$EXECUTION_POLICY_ANCHOR_WRITER")" ] \
    || [ "$(normalize_hex "$pending_release")" != "$(normalize_hex "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT")" ] \
    || [ "$pending_at" = "0" ] || [ "$frozen" != "false" ] || [ "$paused" != "true" ] \
    || [ "$global_sequence" != "0" ] || [ "$(normalize_hex "$global_head")" != "$ZERO_BYTES32" ]; then
    echo "Phase 1 post-state does not contain the exact pending writer release." >&2
    exit 1
  fi
  ledger_status="deployed_paused_exact_writer_release_pending_timelock"
  ledger_policy_state="anchoring_fail_closed_exact_writer_release_pending_timelock"
else
  if [ "$(normalize_hex "$writer")" != "$(normalize_hex "$EXECUTION_POLICY_ANCHOR_WRITER")" ] \
    || [ "$(normalize_hex "$release")" != "$(normalize_hex "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT")" ] \
    || [ "$(normalize_hex "$pending_writer")" != "$ZERO_ADDRESS" ] \
    || [ "$(normalize_hex "$pending_release")" != "$ZERO_BYTES32" ] \
    || [ "$pending_at" != "0" ] || [ "$frozen" != "true" ] || [ "$paused" != "false" ] \
    || [ "$global_sequence" != "0" ] || [ "$(normalize_hex "$global_head")" != "$ZERO_BYTES32" ]; then
    echo "Phase 2 post-state is not the exact active, frozen writer release." >&2
    exit 1
  fi
  ledger_status="deployed_active_exact_writer_release_frozen"
  ledger_policy_state="anchoring_enabled_exact_writer_release_frozen"
fi

RUN_PATH="$CONTRACTS_DIR/broadcast/ConfigureExecutionPolicyAnchor.s.sol/$CHAIN_ID/run-latest.json"
if [ ! -f "$RUN_PATH" ] || [ -L "$RUN_PATH" ]; then
  echo "Missing non-symlink Forge broadcast receipt at $RUN_PATH." >&2
  exit 1
fi
expected_tx_count=1
if [ "$EXECUTION_POLICY_ANCHOR_RELEASE_PHASE" = "2" ]; then
  expected_tx_count=3
fi
if ! release_tx="$(jq -er --argjson expected "$expected_tx_count" '
  (.transactions // null) as $transactions
  | select(($transactions | type) == "array" and ($transactions | length) == $expected)
  | [$transactions[] | (.hash // .transactionHash // "") | ascii_downcase] as $hashes
  | select(($hashes | all(test("^0x[0-9a-f]{64}$") and . != ("0x" + ("0" * 64)))))
  | select(($hashes | unique | length) == $expected)
  | $hashes[-1]
' "$RUN_PATH")"; then
  echo "Forge broadcast receipt does not contain the exact unique transaction set for phase $EXECUTION_POLICY_ANCHOR_RELEASE_PHASE." >&2
  exit 1
fi

receipt_status="$(canonical_receipt_uint release_receipt_status "$(cast receipt "$release_tx" status --confirmations 1 --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
if [ "$receipt_status" != "1" ]; then
  echo "Execution-policy release transaction was not accepted on Base Sepolia." >&2
  exit 1
fi
release_block="$(canonical_receipt_uint release_block "$(cast receipt "$release_tx" blockNumber --confirmations 1 --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
if [ "$release_block" = "0" ]; then
  echo "Execution-policy release receipt has an invalid zero block number." >&2
  exit 1
fi
release_block_timestamp="$(canonical_receipt_uint release_block_timestamp "$(cast block "$release_block" timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
if [ "$release_block_timestamp" = "0" ]; then
  echo "Execution-policy release block has an invalid zero timestamp." >&2
  exit 1
fi
recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Revalidate after the post-state and accepted receipt checks. Refuse to
# overwrite a ledger that another process changed while the transaction ran.
validate_existing_deployment_ledger
if [ "$(deployment_ledger_blob)" != "$ledger_blob_before_broadcast" ]; then
  echo "Deployment ledger changed while the execution-policy release was broadcasting; refusing to overwrite it." >&2
  exit 1
fi

ANCHOR_MANIFEST_TEMP_PATH="$(mktemp "$(dirname "$MANIFEST_PATH")/.execution-policy-anchor-release.tmp.XXXXXX")"
jq \
  --argjson chainId "$CHAIN_ID" \
  --arg anchorAddress "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  --arg runtimeCodeHash "$live_code_hash" \
  --arg sourceCommit "$RELEASE_SHA" \
  --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --argjson phase "$EXECUTION_POLICY_ANCHOR_RELEASE_PHASE" \
  --arg transactionHash "$release_tx" \
  --argjson blockNumber "$release_block" \
  --argjson blockTimestamp "$release_block_timestamp" \
  --arg recordedAt "$recorded_at" \
  --arg status "$ledger_status" \
  --arg policyState "$ledger_policy_state" \
  --arg releaseWriter "$EXECUTION_POLICY_ANCHOR_WRITER" \
  --arg releaseCommitment "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT" \
  --arg writer "$writer" \
  --arg writerReleaseCommitment "$release" \
  --arg pendingWriter "$pending_writer" \
  --arg pendingWriterReleaseCommitment "$pending_release" \
  --argjson pendingWriterActivatesAt "$pending_at" \
  --argjson writerRotationsFrozen "$frozen" \
  --argjson paused "$paused" \
  --argjson globalSequence "$global_sequence" \
  --arg globalHead "$global_head" \
  -f "$MANIFEST_FILTER" \
  "$MANIFEST_PATH" > "$ANCHOR_MANIFEST_TEMP_PATH"
jq empty "$ANCHOR_MANIFEST_TEMP_PATH"
if [ "$(deployment_ledger_blob)" != "$ledger_blob_before_broadcast" ]; then
  echo "Deployment ledger changed during evidence rendering; refusing to overwrite it." >&2
  exit 1
fi
operator_policy_durably_replace_release_ledger "$ANCHOR_MANIFEST_TEMP_PATH" "$MANIFEST_PATH"
rm -f -- "$ANCHOR_MANIFEST_TEMP_PATH"
ANCHOR_MANIFEST_TEMP_PATH=""
operator_policy_release_release_ceremony_lock

echo "Execution-policy anchor release phase $EXECUTION_POLICY_ANCHOR_RELEASE_PHASE completed with exact post-state and append-only ledger evidence."
