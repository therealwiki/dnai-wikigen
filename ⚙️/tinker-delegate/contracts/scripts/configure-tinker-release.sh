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
# Privileged Bash 5 omits ignored exported-function entries from compgen -e.
# Check raw names only after the builtin loader/startup-variable guard above.
# NUL framing keeps newlines in values from becoming names; pipefail makes an
# unavailable or failed fixed env scanner fail closed without printing values.
DNAI_RELEASE_RAW_FUNCTION_MARKER="$(
  set -o pipefail
  /usr/bin/env -0 | while IFS= read -r -d '' DNAI_RELEASE_RAW_ENV_ENTRY; do
    if [[ "${DNAI_RELEASE_RAW_ENV_ENTRY%%=*}" == BASH_FUNC_* ]]; then
      builtin printf '%s\n' forbidden
    fi
  done
)" || {
  echo "Exported environment names could not be enumerated safely." >&2
  exit 1
}
if [ -n "$DNAI_RELEASE_RAW_FUNCTION_MARKER" ]; then
  echo "Shell startup, imported-function, and native-loader control variables are forbidden for release wrappers." >&2
  exit 1
fi
unset DNAI_RELEASE_RAW_FUNCTION_MARKER

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
MAX_TINKER_POLICY_UNITS_PER_OPERATION=10000000000000000000
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-tinker-release-manifest.jq"

dnai_load_keystore_deployment_dotenv "$ROOT_DIR/.env"
dnai_finalize_keystore_deployment_environment BROADCAST

# DEPLOYMENT_MANIFEST_PATH and RELEASE_CEREMONY_LEDGER_PATH are resolved only
# after .env; repository history is never a ceremony fallback.
# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/release-ceremony-paths.sh"
operator_policy_resolve_release_ceremony_paths

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

tmp_manifest=""
cleanup_tinker_release() {
  if [ -n "${tmp_manifest:-}" ]; then
    rm -f -- "$tmp_manifest"
    tmp_manifest=""
  fi
  cleanup_operator_policy_projection
}
trap cleanup_tinker_release EXIT
trap 'cleanup_tinker_release; exit 1' HUP INT TERM

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; the Tinker release policy is never inferred." >&2
    exit 1
  fi
}

normalize_hex() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

validate_address_allow_zero() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "$name must be an Ethereum address." >&2
    exit 1
  fi
}

validate_nonzero_address() {
  local name="$1"
  local value="$2"
  validate_address_allow_zero "$name" "$value"
  if [ "$(normalize_hex "$value")" = "$ZERO_ADDRESS" ]; then
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

validate_sha256_digest() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [[ "$value" =~ ^sha256:0{64}$ ]]; then
    echo "$name must be a nonzero lowercase sha256:<64-hex> digest." >&2
    exit 1
  fi
}

validate_uint() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an unsigned base-10 integer." >&2
    exit 1
  fi
}

decimal_uint_greater_than() {
  local left="$1"
  local right="$2"
  local LC_ALL=C
  if [ "${#left}" -ne "${#right}" ]; then
    [ "${#left}" -gt "${#right}" ]
    return
  fi
  [[ "$left" > "$right" ]]
}

validate_tinker_policy_caps() {
  local max_add="$1"
  local max_spend="$2"
  for value in "$max_add" "$max_spend"; do
    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
      echo "Tinker per-operation policy-unit caps must be canonical positive decimal integers." >&2
      exit 1
    fi
    if decimal_uint_greater_than "$value" "$MAX_TINKER_POLICY_UNITS_PER_OPERATION"; then
      echo "Tinker per-operation policy-unit caps must not exceed $MAX_TINKER_POLICY_UNITS_PER_OPERATION." >&2
      exit 1
    fi
  done
  if decimal_uint_greater_than "$max_spend" "$max_add"; then
    echo "TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI must not exceed TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI." >&2
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

check_release_provenance() {
  require_env RELEASE_SHA
  if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || [ "$RELEASE_SHA" != "$(git -C "$ROOT_DIR" rev-parse HEAD)" ]; then
    echo "RELEASE_SHA must equal the exact lowercase checked-out commit." >&2
    exit 1
  fi
  if [ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]; then
    echo "Refusing Tinker governance broadcast from a dirty source tree." >&2
    exit 1
  fi
}

read_uint() {
  cast call "$TINKER_ENCUMBRANCE_ADDRESS" "$1" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}'
}

read_value() {
  cast call "$TINKER_ENCUMBRANCE_ADDRESS" "$1" --rpc-url "$BASE_SEPOLIA_RPC_URL"
}

for required in forge cast git jq node; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required." >&2
    exit 1
  fi
done

for name in \
  BASE_SEPOLIA_RPC_URL \
  DEPLOYMENT_OPERATOR \
  TINKER_ENCUMBRANCE_ADDRESS \
  TINKER_ENCUMBRANCE_RUNTIME_CODE_HASH \
  TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT \
  TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI \
  TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI \
  TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH \
  TINKER_ENCUMBRANCE_RELEASE_MANAGER \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 \
  TINKER_ENCUMBRANCE_RELEASE_PHASE; do
  require_env "$name"
done

validate_bool BROADCAST "$BROADCAST"
if [[ ! "$TINKER_ENCUMBRANCE_RELEASE_PHASE" =~ ^[12]$ ]]; then
  echo "TINKER_ENCUMBRANCE_RELEASE_PHASE must be exactly 1 or 2." >&2
  exit 1
fi
validate_nonzero_address DEPLOYMENT_OPERATOR "$DEPLOYMENT_OPERATOR"
validate_nonzero_address TINKER_ENCUMBRANCE_ADDRESS "$TINKER_ENCUMBRANCE_ADDRESS"
validate_nonzero_address TINKER_ENCUMBRANCE_RELEASE_MANAGER "$TINKER_ENCUMBRANCE_RELEASE_MANAGER"
validate_bytes32 TINKER_ENCUMBRANCE_RUNTIME_CODE_HASH "$TINKER_ENCUMBRANCE_RUNTIME_CODE_HASH"
validate_bytes32 TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT "$TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT"
validate_bytes32 TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH "$TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH"
validate_sha256_digest OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256"
validate_sha256_digest OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"
validate_uint TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI "$TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI"
validate_uint TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI "$TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI"
validate_tinker_policy_caps \
  "$TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI" \
  "$TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI"

operator_policy_project_and_validate
for policy_env_name in \
  TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT \
  TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI \
  TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI \
  TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH \
  TINKER_ENCUMBRANCE_RELEASE_MANAGER; do
  operator_policy_assert_public_env postDeployEnv "$policy_env_name"
done

if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  echo "Tinker release governance is restricted to the Foundry keystore account named dev." >&2
  exit 1
fi
if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
  echo "Foundry keystore account dev was not found. Use /cast-wallet first." >&2
  exit 1
fi
if [ "$(normalize_hex "$DEPLOYMENT_OPERATOR")" = "$(normalize_hex "$TINKER_ENCUMBRANCE_ADDRESS")" ]; then
  echo "DEPLOYMENT_OPERATOR cannot be the TinkerAccountEncumbrance contract." >&2
  exit 1
fi
if [ "$(normalize_hex "$TINKER_ENCUMBRANCE_RELEASE_MANAGER")" != "$ZERO_ADDRESS" ] \
  && { [ "$(normalize_hex "$TINKER_ENCUMBRANCE_RELEASE_MANAGER")" = "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ] \
    || [ "$(normalize_hex "$TINKER_ENCUMBRANCE_RELEASE_MANAGER")" = "$(normalize_hex "$TINKER_ENCUMBRANCE_ADDRESS")" ]; }; then
  echo "The delegated Tinker manager must be distinct from governance and the contract." >&2
  exit 1
fi

live_chain_id="$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$live_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing Tinker release: RPC chainId $live_chain_id is not Base Sepolia $CHAIN_ID." >&2
  exit 1
fi
live_code_hash="$(cast codehash "$TINKER_ENCUMBRANCE_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_hex "$live_code_hash")" != "$(normalize_hex "$TINKER_ENCUMBRANCE_RUNTIME_CODE_HASH")" ]; then
  echo "TinkerAccountEncumbrance runtime code does not match the reviewed release hash." >&2
  exit 1
fi
live_owner="$(read_value 'owner()(address)')"
if [ "$(normalize_hex "$live_owner")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ]; then
  echo "DEPLOYMENT_OPERATOR is not the live TinkerAccountEncumbrance owner." >&2
  exit 1
fi
if [ "$(normalize_hex "$(read_value 'pendingOwner()(address)')")" != "$ZERO_ADDRESS" ]; then
  echo "A pending ownership transfer blocks the release ceremony." >&2
  exit 1
fi
if [ "$(read_value 'emergencyHalted()(bool)')" != "true" ]; then
  echo "TinkerAccountEncumbrance must remain emergency halted before phase 2." >&2
  exit 1
fi
if [ "$(read_value 'releasePolicyFrozen()(bool)')" != "false" ]; then
  echo "This TinkerAccountEncumbrance already has a frozen release policy." >&2
  exit 1
fi

compose_array="[$TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH]"
manager_array="[$TINKER_ENCUMBRANCE_RELEASE_MANAGER]"
expected_manager_count=1
expected_compose_root="$(cast call "$TINKER_ENCUMBRANCE_ADDRESS" 'computeComposeRoot(bytes32[])(bytes32)' "$compose_array" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
expected_manager_root="$(cast call "$TINKER_ENCUMBRANCE_ADDRESS" 'computeManagerRoot(address[])(bytes32)' "$manager_array" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
empty_compose_root="$(cast call "$TINKER_ENCUMBRANCE_ADDRESS" 'computeComposeRoot(bytes32[])(bytes32)' '[]' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
empty_manager_root="$(cast call "$TINKER_ENCUMBRANCE_ADDRESS" 'computeManagerRoot(address[])(bytes32)' '[]' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
expected_release_commitment="$(cast call "$TINKER_ENCUMBRANCE_ADDRESS" \
  'computeReleasePolicyCommitment(bytes32,uint256,uint256,bytes32,uint256,bytes32,uint256)(bytes32)' \
  "$TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT" \
  "$TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI" \
  "$TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI" \
  "$expected_compose_root" 1 "$expected_manager_root" "$expected_manager_count" \
  --rpc-url "$BASE_SEPOLIA_RPC_URL")"

if [ "$TINKER_ENCUMBRANCE_RELEASE_PHASE" = "1" ]; then
  actual_fresh="$(read_value 'accountCommitment()(bytes32)') $(read_uint 'maxAddBalanceWei()(uint256)') $(read_uint 'maxSpendWei()(uint256)') $(read_uint 'approvedComposeCount()(uint256)') $(read_value 'approvedComposeRoot()(bytes32)') $(read_uint 'managerCount()(uint256)') $(read_value 'managerRoot()(bytes32)') $(read_uint 'pendingComposeCount()(uint256)') $(read_uint 'pendingManagerCount()(uint256)') $(read_uint 'pendingReleasePolicyActivatesAt()(uint64)')"
  expected_fresh="$TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT $TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI $TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI 0 $empty_compose_root 0 $empty_manager_root 0 0 0"
  if [ "$(normalize_hex "$actual_fresh")" != "$(normalize_hex "$expected_fresh")" ]; then
    echo "Phase 1 requires the exact fresh halted Tinker draft with no pending proposal." >&2
    exit 1
  fi
else
  pending_actual="$(read_value 'pendingAccountCommitment()(bytes32)') $(read_uint 'pendingMaxAddBalanceWei()(uint256)') $(read_uint 'pendingMaxSpendWei()(uint256)') $(read_value 'pendingComposeRoot()(bytes32)') $(read_uint 'pendingComposeCount()(uint256)') $(read_value 'pendingManagerRoot()(bytes32)') $(read_uint 'pendingManagerCount()(uint256)') $(read_value 'pendingReleasePolicyCommitment()(bytes32)')"
  pending_expected="$TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT $TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI $TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI $expected_compose_root 1 $expected_manager_root $expected_manager_count $expected_release_commitment"
  if [ "$(normalize_hex "$pending_actual")" != "$(normalize_hex "$pending_expected")" ]; then
    echo "Phase 2 pending release state does not match the reviewed exact commitment." >&2
    exit 1
  fi
  pending_activates_at="$(read_uint 'pendingReleasePolicyActivatesAt()(uint64)')"
  latest_timestamp="$(cast block latest --field timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  if [ "$pending_activates_at" = "0" ] || [ "$pending_activates_at" -gt "$latest_timestamp" ]; then
    echo "The two-day Tinker release timelock has not elapsed." >&2
    exit 1
  fi
fi

if [ "$BROADCAST" = "true" ]; then
  check_release_provenance
  if [ "$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")" = "0" ]; then
    echo "DEPLOYMENT_OPERATOR has no Base Sepolia ETH for governance gas." >&2
    exit 1
  fi
fi

echo "== Tinker exact release phase $TINKER_ENCUMBRANCE_RELEASE_PHASE =="
echo "Chain ID:             $live_chain_id"
echo "Keystore account:     dev"
echo "Operator:             $DEPLOYMENT_OPERATOR"
echo "Encumbrance:          $TINKER_ENCUMBRANCE_ADDRESS"
echo "Account commitment:   $TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT"
echo "Compose root/count:   $expected_compose_root / 1"
echo "Manager root/count:   $expected_manager_root / $expected_manager_count"
echo "Release commitment:   $expected_release_commitment"
echo "Final authority:       $OPERATOR_POLICY_FINAL_AUTHORITY_SHA256"
echo "Review envelope:       $OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"
echo "Policy-unit caps:     add=$TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI spend=$TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI (per operation; not ETH or cumulative)"
echo "Broadcast:            $BROADCAST"

cd "$CONTRACTS_DIR"
forge build --sizes
forge test --match-path test/ConfigureTinkerRelease.t.sol

echo
echo "== Dry run =="
forge script script/ConfigureTinkerRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

if [ "$BROADCAST" != "true" ]; then
  echo "Dry run complete; no chain state changed."
  exit 0
fi

operator_policy_acquire_release_ceremony_lock tinker_release
operator_policy_require_fresh_release_ledger
TINKER_LEDGER_PRE_BROADCAST_BLOB="$(git hash-object --no-filters "$MANIFEST_PATH")"

# Recheck the exact source commit and clean tree immediately before unlocking.
check_release_provenance
unlocked_signer="$(cast wallet address --account dev)"
if [ "$(normalize_hex "$unlocked_signer")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ]; then
  echo "The unlocked dev keystore does not match DEPLOYMENT_OPERATOR." >&2
  exit 1
fi
# Refuse source drift between keystore unlock and the governance transaction.
check_release_provenance

echo
echo "== Broadcast exact timelocked Tinker phase =="
forge script script/ConfigureTinkerRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --account dev \
  --broadcast \
  --slow

active_actual="$(read_value 'accountCommitment()(bytes32)') $(read_uint 'maxAddBalanceWei()(uint256)') $(read_uint 'maxSpendWei()(uint256)') $(read_value 'approvedComposeRoot()(bytes32)') $(read_uint 'approvedComposeCount()(uint256)') $(read_value 'managerRoot()(bytes32)') $(read_uint 'managerCount()(uint256)')"
if [ "$TINKER_ENCUMBRANCE_RELEASE_PHASE" = "1" ]; then
  active_expected="$TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT $TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI $TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI $empty_compose_root 0 $empty_manager_root 0"
  pending_expected="$TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT $TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI $TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI $expected_compose_root 1 $expected_manager_root $expected_manager_count $expected_release_commitment"
  pending_actual="$(read_value 'pendingAccountCommitment()(bytes32)') $(read_uint 'pendingMaxAddBalanceWei()(uint256)') $(read_uint 'pendingMaxSpendWei()(uint256)') $(read_value 'pendingComposeRoot()(bytes32)') $(read_uint 'pendingComposeCount()(uint256)') $(read_value 'pendingManagerRoot()(bytes32)') $(read_uint 'pendingManagerCount()(uint256)') $(read_value 'pendingReleasePolicyCommitment()(bytes32)')"
  if [ "$(normalize_hex "$active_actual")" != "$(normalize_hex "$active_expected")" ] \
    || [ "$(normalize_hex "$pending_actual")" != "$(normalize_hex "$pending_expected")" ] \
    || [ "$(read_value 'emergencyHalted()(bool)')" != "true" ] \
    || [ "$(read_value 'releasePolicyFrozen()(bool)')" != "false" ] \
    || [ "$(read_uint 'pendingReleasePolicyActivatesAt()(uint64)')" = "0" ]; then
    echo "Phase 1 post-state does not expose the exact pending release policy." >&2
    exit 1
  fi
  ledger_status="deployed_halted_release_policy_pending_timelock"
else
  active_expected="$TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT $TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI $TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI $expected_compose_root 1 $expected_manager_root $expected_manager_count"
  release_actual="$(read_value 'releasePolicyCommitment()(bytes32)') $(read_uint 'releaseMaxAddBalanceWei()(uint256)') $(read_uint 'releaseMaxSpendWei()(uint256)') $(read_value 'releaseComposeRoot()(bytes32)') $(read_uint 'releaseComposeCount()(uint256)') $(read_value 'releaseManagerRoot()(bytes32)') $(read_uint 'releaseManagerCount()(uint256)')"
  release_expected="$expected_release_commitment $TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI $TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI $expected_compose_root 1 $expected_manager_root $expected_manager_count"
  if [ "$(normalize_hex "$active_actual")" != "$(normalize_hex "$active_expected")" ] \
    || [ "$(normalize_hex "$release_actual")" != "$(normalize_hex "$release_expected")" ] \
    || [ "$(read_value 'emergencyHalted()(bool)')" != "false" ] \
    || [ "$(read_value 'releasePolicyFrozen()(bool)')" != "true" ] \
    || [ "$(read_uint 'pendingReleasePolicyActivatesAt()(uint64)')" != "0" ] \
    || [ "$(read_uint 'pendingComposeCount()(uint256)')" != "0" ] \
    || [ "$(read_uint 'pendingManagerCount()(uint256)')" != "0" ] \
    || [ "$(normalize_hex "$(read_value 'pendingReleasePolicyCommitment()(bytes32)')")" != "$ZERO_BYTES32" ]; then
    echo "Phase 2 post-state does not match the exact frozen release policy." >&2
    exit 1
  fi
  ledger_status="deployed_exact_release_policy_frozen_active"
fi

RUN_PATH="$CONTRACTS_DIR/broadcast/ConfigureTinkerRelease.s.sol/$CHAIN_ID/run-latest.json"
if [ ! -f "$RUN_PATH" ]; then
  echo "Missing Forge broadcast receipt at $RUN_PATH." >&2
  exit 1
fi
release_tx="$(jq -er '.transactions[-1] | .hash // .transactionHash // empty' "$RUN_PATH")"
release_block="$(cast receipt "$release_tx" blockNumber --rpc-url "$BASE_SEPOLIA_RPC_URL")"
recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ ! -f "$MANIFEST_PATH" ]; then
  echo "Deployment ledger is missing at $MANIFEST_PATH." >&2
  exit 1
fi
ledger_address="$(jq -er '.contracts.tinkerAccountEncumbrance.address' "$MANIFEST_PATH")"
if [ "$(normalize_hex "$ledger_address")" != "$(normalize_hex "$TINKER_ENCUMBRANCE_ADDRESS")" ]; then
  echo "Deployment ledger points at a different TinkerAccountEncumbrance." >&2
  exit 1
fi

pending_owner="$(read_value 'pendingOwner()(address)')"
current_account_commitment="$(read_value 'accountCommitment()(bytes32)')"
current_max_add="$(read_uint 'maxAddBalanceWei()(uint256)')"
current_max_spend="$(read_uint 'maxSpendWei()(uint256)')"
current_compose_root="$(read_value 'approvedComposeRoot()(bytes32)')"
current_compose_count="$(read_uint 'approvedComposeCount()(uint256)')"
current_manager_root="$(read_value 'managerRoot()(bytes32)')"
current_manager_count="$(read_uint 'managerCount()(uint256)')"
release_commitment="$(read_value 'releasePolicyCommitment()(bytes32)')"
release_max_add="$(read_uint 'releaseMaxAddBalanceWei()(uint256)')"
release_max_spend="$(read_uint 'releaseMaxSpendWei()(uint256)')"
release_compose_root="$(read_value 'releaseComposeRoot()(bytes32)')"
release_compose_count="$(read_uint 'releaseComposeCount()(uint256)')"
release_manager_root="$(read_value 'releaseManagerRoot()(bytes32)')"
release_manager_count="$(read_uint 'releaseManagerCount()(uint256)')"
pending_account_commitment="$(read_value 'pendingAccountCommitment()(bytes32)')"
pending_max_add="$(read_uint 'pendingMaxAddBalanceWei()(uint256)')"
pending_max_spend="$(read_uint 'pendingMaxSpendWei()(uint256)')"
pending_compose_root="$(read_value 'pendingComposeRoot()(bytes32)')"
pending_compose_count="$(read_uint 'pendingComposeCount()(uint256)')"
pending_manager_root="$(read_value 'pendingManagerRoot()(bytes32)')"
pending_manager_count="$(read_uint 'pendingManagerCount()(uint256)')"
pending_commitment="$(read_value 'pendingReleasePolicyCommitment()(bytes32)')"
pending_activates_at="$(read_uint 'pendingReleasePolicyActivatesAt()(uint64)')"
release_policy_frozen="$(read_value 'releasePolicyFrozen()(bool)')"
emergency_halted="$(read_value 'emergencyHalted()(bool)')"
policy_state="operations_fail_closed_pending_exact_timelocked_release_policy"
if [ "$release_policy_frozen" = "true" ]; then
  policy_state="exact_timelocked_release_policy_frozen_active"
fi
tmp_manifest="$(mktemp "${MANIFEST_PATH}.tmp.XXXXXX")"
jq \
  --arg status "$ledger_status" \
  --arg encumbranceAddress "$TINKER_ENCUMBRANCE_ADDRESS" \
  --arg runtimeCodeHash "$live_code_hash" \
  --argjson phase "$TINKER_ENCUMBRANCE_RELEASE_PHASE" \
  --arg tx "$release_tx" \
  --argjson block "$release_block" \
  --arg recordedAt "$recorded_at" \
  --arg sourceCommit "$RELEASE_SHA" \
  --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --arg policyState "$policy_state" \
  --arg pendingOwner "$pending_owner" \
  --arg accountCommitment "$current_account_commitment" \
  --arg maxAddBalanceWei "$current_max_add" \
  --arg maxSpendWei "$current_max_spend" \
  --arg composeHash "$TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH" \
  --arg composeRoot "$current_compose_root" \
  --argjson composeCount "$current_compose_count" \
  --arg manager "$TINKER_ENCUMBRANCE_RELEASE_MANAGER" \
  --arg managerRoot "$current_manager_root" \
  --argjson managerCount "$current_manager_count" \
  --arg releaseCommitment "$release_commitment" \
  --arg releaseMaxAddBalanceWei "$release_max_add" \
  --arg releaseMaxSpendWei "$release_max_spend" \
  --arg releaseComposeRoot "$release_compose_root" \
  --argjson releaseComposeCount "$release_compose_count" \
  --arg releaseManagerRoot "$release_manager_root" \
  --argjson releaseManagerCount "$release_manager_count" \
  --arg pendingAccountCommitment "$pending_account_commitment" \
  --arg pendingMaxAddBalanceWei "$pending_max_add" \
  --arg pendingMaxSpendWei "$pending_max_spend" \
  --arg pendingComposeRoot "$pending_compose_root" \
  --argjson pendingComposeCount "$pending_compose_count" \
  --arg pendingManagerRoot "$pending_manager_root" \
  --argjson pendingManagerCount "$pending_manager_count" \
  --arg pendingCommitment "$pending_commitment" \
  --argjson pendingActivatesAt "$pending_activates_at" \
  --argjson releasePolicyFrozen "$release_policy_frozen" \
  --argjson emergencyHalted "$emergency_halted" \
  -f "$MANIFEST_FILTER" "$MANIFEST_PATH" > "$tmp_manifest"
if [ "$(git hash-object --no-filters "$MANIFEST_PATH")" != "$TINKER_LEDGER_PRE_BROADCAST_BLOB" ]; then
  echo "Deployment ledger changed while the Tinker release lock was held; refusing durable replacement." >&2
  exit 1
fi
operator_policy_durably_replace_release_ledger "$tmp_manifest" "$MANIFEST_PATH"
rm -f -- "$tmp_manifest"
tmp_manifest=""
operator_policy_release_release_ceremony_lock

echo "Tinker release phase $TINKER_ENCUMBRANCE_RELEASE_PHASE completed with exact post-state and append-only ledger evidence."
