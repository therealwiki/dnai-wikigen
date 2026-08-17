#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
CHAIN_ID=84532
ACCOUNT=dev
MAX_SAFE_JSON_INTEGER=9007199254740991
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-challenge-registry-release-manifest.jq"
CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH=""
CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON=""
OBSERVED_CATALOG_JSON="[]"
OBSERVED_STATE_BLOCK_NUMBER=""
OBSERVED_STATE_BLOCK_HASH=""
OBSERVED_STATE_BLOCK_TIMESTAMP=""
LATEST_STATE_BLOCK_NUMBER=""
LATEST_STATE_BLOCK_HASH=""
LATEST_STATE_BLOCK_TIMESTAMP=""

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

# DEPLOYMENT_MANIFEST_PATH and RELEASE_CEREMONY_LEDGER_PATH are resolved only
# after .env; repository history is never a ceremony fallback.
# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/release-ceremony-paths.sh"
operator_policy_resolve_release_ceremony_paths

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

cleanup_challenge_registry_release() {
  if [ -n "${CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH:-}" ]; then
    rm -f -- "$CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH"
    CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH=""
  fi
  CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON=""
  OBSERVED_CATALOG_JSON="[]"
  OBSERVED_STATE_BLOCK_NUMBER=""
  OBSERVED_STATE_BLOCK_HASH=""
  OBSERVED_STATE_BLOCK_TIMESTAMP=""
  LATEST_STATE_BLOCK_NUMBER=""
  LATEST_STATE_BLOCK_HASH=""
  LATEST_STATE_BLOCK_TIMESTAMP=""
  cleanup_operator_policy_projection
}

trap cleanup_challenge_registry_release EXIT
trap 'cleanup_challenge_registry_release; exit 1' HUP INT TERM

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; ChallengeRegistry release authority is never inferred." >&2
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
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] || [[ "$value" =~ ^0x0{64}$ ]]; then
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
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [[ "$value" =~ ^sha256:0{64}$ ]]; then
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

validate_external_evidence_paths() {
  local root_real manifest_dir manifest_base manifest_dir_real broadcast_real
  if [ -z "${DEPLOYMENT_MANIFEST_PATH:-}" ] || [[ "$MANIFEST_PATH" != /* ]]; then
    echo "BROADCAST=true requires an explicit absolute DEPLOYMENT_MANIFEST_PATH outside the source repository." >&2
    exit 1
  fi
  manifest_dir="$(dirname "$MANIFEST_PATH")"
  manifest_base="$(basename "$MANIFEST_PATH")"
  if [ ! -d "$manifest_dir" ] || [ -L "$manifest_dir" ]; then
    echo "The external deployment-ledger directory must be an existing non-symlink directory." >&2
    exit 1
  fi
  manifest_dir_real="$(cd "$manifest_dir" && pwd -P)"
  if [ "$manifest_dir" != "$manifest_dir_real" ] || [ "$MANIFEST_PATH" != "$manifest_dir_real/$manifest_base" ]; then
    echo "DEPLOYMENT_MANIFEST_PATH must be canonical and contain no symlinked path component." >&2
    exit 1
  fi
  root_real="$(cd "$ROOT_DIR" && pwd -P)"
  case "$MANIFEST_PATH" in
    "$root_real" | "$root_real"/*)
      echo "ChallengeRegistry broadcast evidence must not mutate the reviewed source repository." >&2
      exit 1
      ;;
  esac

  require_env FOUNDRY_BROADCAST
  if [[ "$FOUNDRY_BROADCAST" != /* ]] || [ ! -d "$FOUNDRY_BROADCAST" ] \
    || [ -L "$FOUNDRY_BROADCAST" ] || [ ! -r "$FOUNDRY_BROADCAST" ] \
    || [ ! -w "$FOUNDRY_BROADCAST" ] || [ ! -x "$FOUNDRY_BROADCAST" ]; then
    echo "FOUNDRY_BROADCAST must be an existing readable, writable, executable non-symlink directory." >&2
    exit 1
  fi
  broadcast_real="$(cd "$FOUNDRY_BROADCAST" && pwd -P)"
  if [ "$FOUNDRY_BROADCAST" != "$broadcast_real" ]; then
    echo "FOUNDRY_BROADCAST must be canonical and contain no symlinked path component." >&2
    exit 1
  fi
  case "$FOUNDRY_BROADCAST" in
    "$root_real" | "$root_real"/*)
      echo "FOUNDRY_BROADCAST must remain outside the reviewed source repository." >&2
      exit 1
      ;;
  esac
  export FOUNDRY_BROADCAST
}

deployment_ledger_blob() {
  git hash-object --no-filters "$MANIFEST_PATH"
}

validate_existing_deployment_ledger() {
  local manifest_link_count
  if [ ! -f "$MANIFEST_PATH" ] || [ -L "$MANIFEST_PATH" ] || [ ! -r "$MANIFEST_PATH" ] || [ ! -w "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be an existing readable, writable, non-symlink regular file at $MANIFEST_PATH." >&2
    exit 1
  fi
  if manifest_link_count="$(stat -f '%l' "$MANIFEST_PATH" 2>/dev/null)"; then
    :
  else
    manifest_link_count="$(stat -c '%h' "$MANIFEST_PATH")"
  fi
  if [ "$manifest_link_count" != "1" ]; then
    echo "Deployment ledger must not be a hard link." >&2
    exit 1
  fi
  if ! jq -e \
    --arg registry "$CHALLENGE_REGISTRY_ADDRESS" \
    --arg runtime "$CHALLENGE_REGISTRY_RUNTIME_CODE_HASH" \
    --arg source "$RELEASE_SHA" '
      type == "object"
      and .network.chainId == 84532
      and ((.contracts.challengeRegistry.address // "") | ascii_downcase) == ($registry | ascii_downcase)
      and ((.contracts.challengeRegistry.runtimeCodeHash // "") | ascii_downcase) == ($runtime | ascii_downcase)
      and .contracts.challengeRegistry.sourceCommit == $source
      and .freshDeployment.contractSuite.sourceCommit == $source
      and ((.challengeRegistryReleaseHistory // []) | type) == "array"
    ' "$MANIFEST_PATH" >/dev/null; then
    echo "Deployment ledger chain, ChallengeRegistry address, runtime, or source does not match this release." >&2
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
    echo "Refusing ChallengeRegistry governance broadcast from a dirty source tree." >&2
    exit 1
  fi
}

for required in forge cast git jq node shasum; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required." >&2
    exit 1
  fi
done

for name in \
  BASE_SEPOLIA_RPC_URL \
  DEPLOYMENT_OPERATOR \
  CHALLENGE_REGISTRY_ADDRESS \
  CHALLENGE_REGISTRY_RUNTIME_CODE_HASH \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 \
  CHALLENGE_REGISTRY_RELEASE_PHASE; do
  require_env "$name"
done

BROADCAST="${BROADCAST:-false}"
validate_bool BROADCAST "$BROADCAST"
if [ "$BROADCAST" = "true" ]; then
  validate_external_evidence_paths
fi
if [[ ! "$CHALLENGE_REGISTRY_RELEASE_PHASE" =~ ^[12]$ ]]; then
  echo "CHALLENGE_REGISTRY_RELEASE_PHASE must be exactly 1 or 2." >&2
  exit 1
fi
validate_address DEPLOYMENT_OPERATOR "$DEPLOYMENT_OPERATOR"
validate_address CHALLENGE_REGISTRY_ADDRESS "$CHALLENGE_REGISTRY_ADDRESS"
validate_bytes32 CHALLENGE_REGISTRY_RUNTIME_CODE_HASH "$CHALLENGE_REGISTRY_RUNTIME_CODE_HASH"
validate_sha256_digest OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256"
validate_sha256_digest OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"

# Validate the intent, final authority, and renewable review envelope before
# any chain read, wallet access, Forge simulation, or operator-owned parsing.
operator_policy_project_and_validate
if ! CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON="$(node \
  "$ROOT_DIR/scripts/challenge-registry-authority-projector.mjs" \
  --final-authority "$FINAL_RELEASE_AUTHORITY_CORE_PATH" \
  --final-authority-sha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --release-sha "$RELEASE_SHA")"; then
  echo "Exact ChallengeRegistry final-authority projection failed." >&2
  exit 1
fi
if [ "${#CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON}" -gt 65536 ] || ! jq -e \
  --arg registry "$CHALLENGE_REGISTRY_ADDRESS" \
  --arg runtime "$CHALLENGE_REGISTRY_RUNTIME_CODE_HASH" \
  --arg operator "$DEPLOYMENT_OPERATOR" \
  --arg source "$RELEASE_SHA" \
  --arg authority "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" '
    keys == ["chainId", "entries", "finalAuthoritySha256", "registry", "releaseSha", "schema"]
    and .schema == "dnai.challenge-registry-authority-projection.v1"
    and .chainId == 84532
    and .releaseSha == $source
    and .finalAuthoritySha256 == $authority
    and (.registry | keys) == ["address", "expectedChallengeCount", "minimumVersionReviewDelaySeconds", "owner", "pendingOwner", "registryPaused", "runtimeCodeHash"]
    and (.registry.address | ascii_downcase) == ($registry | ascii_downcase)
    and (.registry.runtimeCodeHash | ascii_downcase) == ($runtime | ascii_downcase)
    and (.registry.owner | ascii_downcase) == ($operator | ascii_downcase)
    and (.registry.pendingOwner | ascii_downcase) == "0x0000000000000000000000000000000000000000"
    and (.registry.registryPaused | not)
    and .registry.minimumVersionReviewDelaySeconds == 172800
    and (.entries | type) == "array" and (.entries | length) >= 1 and (.entries | length) <= 32
    and .registry.expectedChallengeCount == (.entries | length)
    and ([range(0; .entries | length) as $index
      | .entries[$index]
      | keys == ["catalogKey", "catalogManifestHash", "challengeId", "configurationFrozen", "controller", "evaluatorCommitment", "lifecycle", "metadataHash", "metadataURI", "paused", "pendingController", "releasePolicyCommitment", "sealedArtifactCommitment", "version"]
        and .challengeId == ($index + 1)
        and .version == 1
        and .lifecycle == "open"
        and (.paused | not)
        and .configurationFrozen
        and (.pendingController | ascii_downcase) == "0x0000000000000000000000000000000000000000"
        and (.catalogManifestHash | test("^0x[0-9a-f]{64}$"))
        and (.metadataHash | ascii_downcase) == (.catalogManifestHash | ascii_downcase)
    ] | all)
  ' <<<"$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON" >/dev/null; then
  echo "ChallengeRegistry authority projector returned a malformed, incomplete, or mismatched catalog." >&2
  exit 1
fi
export CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON
catalog_count="$(jq -er '.entries | length' <<<"$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON")"
validate_safe_json_uint catalog_count "$catalog_count"
catalog_projection_sha256="sha256:$(printf '%s' "$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON" | shasum -a 256 | awk '{print $1}')"
validate_sha256_digest catalog_projection_sha256 "$catalog_projection_sha256"

revalidate_release_authority_and_catalog() {
  local revalidated_catalog revalidated_digest
  operator_policy_project_and_validate
  if ! revalidated_catalog="$(node \
    "$ROOT_DIR/scripts/challenge-registry-authority-projector.mjs" \
    --final-authority "$FINAL_RELEASE_AUTHORITY_CORE_PATH" \
    --final-authority-sha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --release-sha "$RELEASE_SHA")"; then
    echo "ChallengeRegistry authority revalidation failed after operator delay." >&2
    exit 1
  fi
  revalidated_digest="sha256:$(printf '%s' "$revalidated_catalog" | shasum -a 256 | awk '{print $1}')"
  if [ "$revalidated_catalog" != "$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON" ] \
    || [ "$revalidated_digest" != "$catalog_projection_sha256" ]; then
    echo "ChallengeRegistry final authority or exact catalog projection changed during the ceremony." >&2
    exit 1
  fi
}

if [ "$BROADCAST" = "true" ]; then
  validate_existing_deployment_ledger
elif [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "2" ]; then
  validate_existing_deployment_ledger
fi

if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  echo "ChallengeRegistry release governance is restricted to the Foundry keystore account named dev." >&2
  exit 1
fi
if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
  echo "Foundry keystore account dev was not found. Use /cast-wallet first." >&2
  exit 1
fi

live_chain_id="$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$live_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing ChallengeRegistry release: RPC chainId $live_chain_id is not Base Sepolia $CHAIN_ID." >&2
  exit 1
fi
live_code_hash="$(cast codehash "$CHALLENGE_REGISTRY_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_hex "$live_code_hash")" != "$(normalize_hex "$CHALLENGE_REGISTRY_RUNTIME_CODE_HASH")" ]; then
  echo "ChallengeRegistry runtime code does not match the reviewed release hash." >&2
  exit 1
fi
live_owner="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'owner()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_hex "$live_owner")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ]; then
  echo "DEPLOYMENT_OPERATOR is not the live ChallengeRegistry owner." >&2
  exit 1
fi

rpc_uint_to_decimal() {
  local value="$1"
  case "$value" in
    0x*) cast to-dec "$value" ;;
    *) printf '%s' "$value" ;;
  esac
}

pin_state_block() {
  local block_tag="${1:-latest}"
  local raw_number raw_timestamp
  raw_number="$(cast block "$block_tag" --field number --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  OBSERVED_STATE_BLOCK_NUMBER="$(rpc_uint_to_decimal "$raw_number")"
  validate_safe_json_uint OBSERVED_STATE_BLOCK_NUMBER "$OBSERVED_STATE_BLOCK_NUMBER"
  if [ "$OBSERVED_STATE_BLOCK_NUMBER" = "0" ]; then
    echo "Cannot pin ChallengeRegistry state to genesis block zero." >&2
    exit 1
  fi
  OBSERVED_STATE_BLOCK_HASH="$(cast block "$OBSERVED_STATE_BLOCK_NUMBER" --field hash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  validate_bytes32 OBSERVED_STATE_BLOCK_HASH "$OBSERVED_STATE_BLOCK_HASH"
  raw_timestamp="$(cast block "$OBSERVED_STATE_BLOCK_NUMBER" --field timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  OBSERVED_STATE_BLOCK_TIMESTAMP="$(rpc_uint_to_decimal "$raw_timestamp")"
  validate_safe_json_uint OBSERVED_STATE_BLOCK_TIMESTAMP "$OBSERVED_STATE_BLOCK_TIMESTAMP"
  if [ "$OBSERVED_STATE_BLOCK_TIMESTAMP" = "0" ]; then
    echo "Pinned ChallengeRegistry state block has an invalid timestamp." >&2
    exit 1
  fi
}

assert_state_block_canonical() {
  assert_named_block_canonical "$OBSERVED_STATE_BLOCK_NUMBER" "$OBSERVED_STATE_BLOCK_HASH" "Pinned ChallengeRegistry state"
}

assert_named_block_canonical() {
  local block_number="$1"
  local block_hash="$2"
  local label="$3"
  local canonical_hash
  canonical_hash="$(cast block "$block_number" --field hash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  if [ "$(normalize_hex "$canonical_hash")" != "$(normalize_hex "$block_hash")" ]; then
    echo "$label block is no longer canonical." >&2
    exit 1
  fi
}

read_challenge_json() {
  local challenge_id="$1"
  local state_block="$2"
  cast call "$CHALLENGE_REGISTRY_ADDRESS" \
    'getChallenge(uint256)((address,address,uint8,uint64,uint64,uint32,bool,bool))' \
    "$challenge_id" --json --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL" \
    | jq -c 'if length == 1 and (.[0] | type) == "array" then .[0] else . end'
}

read_version_json() {
  local challenge_id="$1"
  local state_block="$2"
  cast call "$CHALLENGE_REGISTRY_ADDRESS" \
    'getVersion(uint256,uint32)((string,bytes32,bytes32,bytes32,bytes32,uint64))' \
    "$challenge_id" 1 --json --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL" \
    | jq -c 'if length == 1 and (.[0] | type) == "array" then .[0] else . end'
}

validate_registry_common_state() {
  local state_block="$1"
  local snapshot_chain_id snapshot_code_hash snapshot_owner pending_owner registry_paused review_delay challenge_count next_challenge_id
  snapshot_chain_id="$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  snapshot_code_hash="$(cast codehash "$CHALLENGE_REGISTRY_ADDRESS" --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  snapshot_owner="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'owner()(address)' --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  pending_owner="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'pendingOwner()(address)' --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  registry_paused="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'registryPaused()(bool)' --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  review_delay="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'MIN_VERSION_REVIEW_DELAY()(uint64)' --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
  challenge_count="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'challengeCount()(uint256)' --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
  next_challenge_id="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'nextChallengeId()(uint256)' --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
  for value_name in review_delay challenge_count next_challenge_id; do
    validate_safe_json_uint "$value_name" "${!value_name}"
  done
  if [ "$snapshot_chain_id" != "$CHAIN_ID" ] \
    || [ "$(normalize_hex "$snapshot_code_hash")" != "$(normalize_hex "$CHALLENGE_REGISTRY_RUNTIME_CODE_HASH")" ] \
    || [ "$(normalize_hex "$snapshot_owner")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ] \
    || [ "$(normalize_hex "$pending_owner")" != "$ZERO_ADDRESS" ] \
    || [ "$registry_paused" != "false" ] || [ "$review_delay" != "172800" ]; then
    echo "ChallengeRegistry chain, runtime, owner-transfer, pause, or review-delay state is not the reviewed release state." >&2
    exit 1
  fi
  printf '%s %s' "$challenge_count" "$next_challenge_id"
}

collect_and_validate_catalog_state() {
  local expected_state="$1"
  local require_elapsed="$2"
  local state_block="$3"
  local common challenge_count next_challenge_id observed
  common="$(validate_registry_common_state "$state_block")"
  challenge_count="${common%% *}"
  next_challenge_id="${common##* }"
  if [ "$challenge_count" != "$catalog_count" ] || [ "$next_challenge_id" != "$((catalog_count + 1))" ]; then
    echo "ChallengeRegistry challenge count is not the exact contiguous authority catalog." >&2
    exit 1
  fi
  observed='[]'

  local index
  for ((index = 0; index < catalog_count; index++)); do
    local challenge_id expected challenge_json version_json controller pending lifecycle created updated version paused frozen
    local controller_paused governance_paused eligible metadata_uri metadata_hash sealed evaluator release version_created
    challenge_id=$((index + 1))
    expected="$(jq -c --argjson index "$index" '.entries[$index]' <<<"$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON")"
    challenge_json="$(read_challenge_json "$challenge_id" "$state_block")"
    version_json="$(read_version_json "$challenge_id" "$state_block")"
    if ! jq -e 'type == "array" and length == 8' <<<"$challenge_json" >/dev/null \
      || ! jq -e 'type == "array" and length == 6' <<<"$version_json" >/dev/null; then
      echo "ChallengeRegistry returned an unexpected tuple shape for challenge $challenge_id." >&2
      exit 1
    fi
    controller="$(jq -er '.[0]' <<<"$challenge_json")"
    pending="$(jq -er '.[1]' <<<"$challenge_json")"
    lifecycle="$(jq -er '.[2] | tostring' <<<"$challenge_json")"
    created="$(jq -er '.[3] | tostring' <<<"$challenge_json")"
    updated="$(jq -er '.[4] | tostring' <<<"$challenge_json")"
    version="$(jq -er '.[5] | tostring' <<<"$challenge_json")"
    paused="$(jq -er '.[6] | tostring' <<<"$challenge_json")"
    frozen="$(jq -er '.[7] | tostring' <<<"$challenge_json")"
    controller_paused="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'controllerChallengePaused(uint256)(bool)' "$challenge_id" --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    governance_paused="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'governanceChallengePaused(uint256)(bool)' "$challenge_id" --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    eligible="$(cast call "$CHALLENGE_REGISTRY_ADDRESS" 'reviewEligibleAt(uint256)(uint64)' "$challenge_id" --block "$state_block" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
    metadata_uri="$(jq -er '.[0]' <<<"$version_json")"
    metadata_hash="$(jq -er '.[1]' <<<"$version_json")"
    sealed="$(jq -er '.[2]' <<<"$version_json")"
    evaluator="$(jq -er '.[3]' <<<"$version_json")"
    release="$(jq -er '.[4]' <<<"$version_json")"
    version_created="$(jq -er '.[5] | tostring' <<<"$version_json")"
    for value_name in created updated version eligible version_created; do
      validate_safe_json_uint "$value_name" "${!value_name}"
    done
    if [ "$(normalize_hex "$controller")" != "$(jq -r '.controller | ascii_downcase' <<<"$expected")" ] \
      || [ "$(normalize_hex "$pending")" != "$ZERO_ADDRESS" ] || [ "$version" != "1" ] \
      || [ "$paused" != "false" ] || [ "$controller_paused" != "false" ] \
      || [ "$governance_paused" != "false" ] || [ "$created" = "0" ] \
      || [ "$version_created" != "$created" ] || [ "$eligible" != "$((created + 172800))" ] \
      || [ "$metadata_uri" != "$(jq -r '.metadataURI' <<<"$expected")" ] \
      || [ "$(normalize_hex "$metadata_hash")" != "$(jq -r '.metadataHash | ascii_downcase' <<<"$expected")" ] \
      || [ "$(normalize_hex "$sealed")" != "$(jq -r '.sealedArtifactCommitment | ascii_downcase' <<<"$expected")" ] \
      || [ "$(normalize_hex "$evaluator")" != "$(jq -r '.evaluatorCommitment | ascii_downcase' <<<"$expected")" ] \
      || [ "$(normalize_hex "$release")" != "$(jq -r '.releasePolicyCommitment | ascii_downcase' <<<"$expected")" ]; then
      echo "Challenge $challenge_id does not match the exact reviewed version-1 tuple." >&2
      exit 1
    fi
    if [ "$expected_state" = "draft" ]; then
      if [ "$lifecycle" != "0" ] || [ "$frozen" != "false" ] || [ "$updated" != "$created" ]; then
        echo "Challenge $challenge_id is not the exact untouched phase-1 draft." >&2
        exit 1
      fi
    else
      if [ "$lifecycle" != "1" ] || [ "$frozen" != "true" ] || [ "$updated" -lt "$eligible" ]; then
        echo "Challenge $challenge_id is not the exact frozen open release." >&2
        exit 1
      fi
    fi
    if [ "$require_elapsed" = "true" ] && [ "$eligible" -gt "$OBSERVED_STATE_BLOCK_TIMESTAMP" ]; then
      echo "Challenge $challenge_id version review timelock has not elapsed." >&2
      exit 1
    fi
    observed="$(jq -c \
      --argjson current "$observed" \
      --arg catalogKey "$(jq -r '.catalogKey' <<<"$expected")" \
      --argjson challengeId "$challenge_id" \
      --arg controller "$controller" \
      --arg pendingController "$pending" \
      --arg lifecycleName "$expected_state" \
      --argjson createdAt "$created" \
      --argjson updatedAt "$updated" \
      --argjson latestVersion "$version" \
      --argjson paused "$paused" \
      --argjson configurationFrozen "$frozen" \
      --argjson controllerPaused "$controller_paused" \
      --argjson governancePaused "$governance_paused" \
      --argjson reviewEligibleAt "$eligible" \
      --arg metadataURI "$metadata_uri" \
      --arg metadataHash "$metadata_hash" \
      --arg sealedArtifactCommitment "$sealed" \
      --arg evaluatorCommitment "$evaluator" \
      --arg releasePolicyCommitment "$release" \
      '$current + [{catalogKey: $catalogKey, challengeId: $challengeId, controller: $controller, pendingController: $pendingController, lifecycle: $lifecycleName, createdAt: $createdAt, updatedAt: $updatedAt, latestVersion: $latestVersion, paused: $paused, configurationFrozen: $configurationFrozen, controllerPaused: $controllerPaused, governancePaused: $governancePaused, reviewEligibleAt: $reviewEligibleAt, metadataURI: $metadataURI, metadataHash: $metadataHash, sealedArtifactCommitment: $sealedArtifactCommitment, evaluatorCommitment: $evaluatorCommitment, releasePolicyCommitment: $releasePolicyCommitment}]' <<<"{}")"
  done
  OBSERVED_CATALOG_JSON="$observed"
}

capture_and_validate_catalog_state() {
  local expected_state="$1"
  local require_elapsed="$2"
  local block_tag="${3:-latest}"
  pin_state_block "$block_tag"
  collect_and_validate_catalog_state "$expected_state" "$require_elapsed" "$OBSERVED_STATE_BLOCK_NUMBER"
  assert_state_block_canonical
}

wait_for_finalized_receipts() {
  local highest_receipt_block="$1"
  local started_at now finalized_block
  started_at="$(date +%s)"
  while true; do
    finalized_block="$(rpc_uint_to_decimal "$(cast block finalized --field number --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
    validate_safe_json_uint finalized_block "$finalized_block"
    if [ "$finalized_block" -ge "$highest_receipt_block" ]; then
      return
    fi
    now="$(date +%s)"
    if [ $((now - started_at)) -ge 3600 ]; then
      echo "ChallengeRegistry phase transactions did not reach a finalized checkpoint within one hour; evidence was not appended." >&2
      exit 1
    fi
    sleep 5
  done
}

assert_receipt_blocks_canonical() {
  local block_number block_hash canonical_hash
  while IFS=$'\t' read -r block_number block_hash; do
    canonical_hash="$(cast block "$block_number" --field hash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    if [ "$(normalize_hex "$canonical_hash")" != "$(normalize_hex "$block_hash")" ]; then
      echo "A ChallengeRegistry transaction receipt block is no longer canonical after finalization." >&2
      exit 1
    fi
  done < <(jq -r '.[] | [.blockNumber, .blockHash] | @tsv' <<<"$transaction_receipts")
}

validate_release_history_prestate() {
  if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
    if ! jq -e \
      --arg registry "$CHALLENGE_REGISTRY_ADDRESS" '
        [(.challengeRegistryReleaseHistory // [])[]
          | select(((.challengeRegistryAddress // "") | ascii_downcase) == ($registry | ascii_downcase))] as $history
        | ($history | length) == 0
          and (.contracts.challengeRegistry.latestReleasePhase // 0) == 0
      ' "$MANIFEST_PATH" >/dev/null; then
      echo "Phase 1 requires a deployment ledger with no prior ChallengeRegistry release phase." >&2
      exit 1
    fi
    return
  fi

  local phase_one_record recorded_block recorded_hash canonical_hash recorded_timestamp
  local recorded_latest_block recorded_latest_hash recorded_latest_timestamp current_finalized receipt_count index
  if ! phase_one_record="$(jq -cer \
    --argjson chainId "$CHAIN_ID" \
    --arg registry "$CHALLENGE_REGISTRY_ADDRESS" \
    --arg runtime "$CHALLENGE_REGISTRY_RUNTIME_CODE_HASH" \
    --arg operator "$DEPLOYMENT_OPERATOR" \
    --arg source "$RELEASE_SHA" \
    --arg authority "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --arg projection "$catalog_projection_sha256" \
    --argjson catalog "$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON" \
    --argjson observed "$OBSERVED_CATALOG_JSON" '
      [(.challengeRegistryReleaseHistory // [])[]
        | select(((.challengeRegistryAddress // "") | ascii_downcase) == ($registry | ascii_downcase))] as $history
      | if ($history | length) != 1 then error("expected exactly one registry history record") else $history[0] end
      | . as $record
      | select(
          keys == [
            "authorityCatalog", "catalogProjectionSha256", "challengeRegistryAddress", "chainId",
            "finalAuthoritySha256", "kind", "phase", "policyState", "postState", "recordedAt",
            "reviewEnvelopeSha256", "runtimeCodeHash", "sourceCommit", "status", "transactionReceipts"
          ]
          and .kind == "challenge_registry_exact_genesis_phase"
          and .chainId == $chainId
          and ((.challengeRegistryAddress | ascii_downcase) == ($registry | ascii_downcase))
          and ((.runtimeCodeHash | ascii_downcase) == ($runtime | ascii_downcase))
          and .sourceCommit == $source
          and (.reviewEnvelopeSha256 | type) == "string"
          and (.reviewEnvelopeSha256 | test("^sha256:[0-9a-f]{64}$"))
          and .reviewEnvelopeSha256 != ("sha256:" + ("0" * 64))
          and .finalAuthoritySha256 == $authority
          and .catalogProjectionSha256 == $projection
          and .phase == 1
          and .status == "deployed_exact_arena_genesis_pending_version_review"
          and .policyState == "arena_genesis_fail_closed_pending_two_day_version_review"
          and .authorityCatalog == $catalog.entries
          and (.postState | keys) == [
            "blockHash", "blockNumber", "blockTimestamp", "challengeCount", "challenges",
            "latestCheckBlockHash", "latestCheckBlockNumber", "latestCheckBlockTimestamp",
            "minimumVersionReviewDelaySeconds", "nextChallengeId", "owner", "pendingOwner", "registryPaused"
          ]
          and ((.postState.owner | ascii_downcase) == ($operator | ascii_downcase))
          and ((.postState.pendingOwner | ascii_downcase) == "0x0000000000000000000000000000000000000000")
          and (.postState.registryPaused | not)
          and .postState.challengeCount == ($catalog.entries | length)
          and .postState.nextChallengeId == (($catalog.entries | length) + 1)
          and .postState.minimumVersionReviewDelaySeconds == 172800
          and .postState.challenges == $observed
          and (.postState.blockNumber | type) == "number" and .postState.blockNumber > 0
          and (.postState.blockTimestamp | type) == "number" and .postState.blockTimestamp > 0
          and (.postState.blockHash | type) == "string" and (.postState.blockHash | test("^0x[0-9a-fA-F]{64}$"))
          and (.postState.latestCheckBlockNumber | type) == "number"
          and .postState.latestCheckBlockNumber >= .postState.blockNumber
          and (.postState.latestCheckBlockTimestamp | type) == "number"
          and .postState.latestCheckBlockTimestamp >= .postState.blockTimestamp
          and (.postState.latestCheckBlockHash | type) == "string"
          and (.postState.latestCheckBlockHash | test("^0x[0-9a-fA-F]{64}$"))
          and (.transactionReceipts | type) == "array"
          and (.transactionReceipts | length) == ($catalog.entries | length)
          and ([range(0; .transactionReceipts | length) as $index
            | $record.transactionReceipts[$index]
            | keys == ["blockHash", "blockNumber", "blockTimestamp", "calldataHash", "challengeId", "function", "transactionHash", "transactionIndex"]
              and .challengeId == ($index + 1)
              and .function == "createChallenge"
              and .blockTimestamp == $observed[$index].createdAt
              and .blockNumber <= $record.postState.blockNumber
          ] | all)
        )
    ' "$MANIFEST_PATH")"; then
    echo "Phase 2 requires the one exact, independently verifiable phase-1 ledger record." >&2
    exit 1
  fi
  if ! jq -e '.contracts.challengeRegistry.latestReleasePhase == 1' "$MANIFEST_PATH" >/dev/null; then
    echo "Phase 2 requires current ChallengeRegistry ledger phase 1." >&2
    exit 1
  fi

  recorded_block="$(jq -er '.postState.blockNumber | tostring' <<<"$phase_one_record")"
  recorded_hash="$(jq -er '.postState.blockHash' <<<"$phase_one_record")"
  recorded_timestamp="$(jq -er '.postState.blockTimestamp | tostring' <<<"$phase_one_record")"
  recorded_latest_block="$(jq -er '.postState.latestCheckBlockNumber | tostring' <<<"$phase_one_record")"
  recorded_latest_hash="$(jq -er '.postState.latestCheckBlockHash' <<<"$phase_one_record")"
  recorded_latest_timestamp="$(jq -er '.postState.latestCheckBlockTimestamp | tostring' <<<"$phase_one_record")"
  validate_safe_json_uint recorded_block "$recorded_block"
  validate_safe_json_uint recorded_timestamp "$recorded_timestamp"
  validate_bytes32 recorded_hash "$recorded_hash"
  validate_safe_json_uint recorded_latest_block "$recorded_latest_block"
  validate_safe_json_uint recorded_latest_timestamp "$recorded_latest_timestamp"
  validate_bytes32 recorded_latest_hash "$recorded_latest_hash"
  current_finalized="$(rpc_uint_to_decimal "$(cast block finalized --field number --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
  validate_safe_json_uint current_finalized "$current_finalized"
  if [ "$recorded_block" -gt "$current_finalized" ] || [ "$recorded_latest_block" -gt "$current_finalized" ]; then
    echo "Phase-1 ChallengeRegistry evidence is not covered by the current finalized checkpoint." >&2
    exit 1
  fi
  canonical_hash="$(cast block "$recorded_block" --field hash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  if [ "$(normalize_hex "$canonical_hash")" != "$(normalize_hex "$recorded_hash")" ]; then
    echo "Phase-1 ChallengeRegistry poststate block is no longer canonical." >&2
    exit 1
  fi
  canonical_hash="$(cast block "$recorded_latest_block" --field hash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  if [ "$(normalize_hex "$canonical_hash")" != "$(normalize_hex "$recorded_latest_hash")" ] \
    || [ "$(rpc_uint_to_decimal "$(cast block "$recorded_latest_block" --field timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")")" != "$recorded_latest_timestamp" ]; then
    echo "Phase-1 ChallengeRegistry latest-state recheck block is no longer canonical." >&2
    exit 1
  fi
  if [ "$(rpc_uint_to_decimal "$(cast block "$recorded_block" --field timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")")" != "$recorded_timestamp" ]; then
    echo "Phase-1 ChallengeRegistry poststate block timestamp does not match the chain." >&2
    exit 1
  fi

  receipt_count="$(jq -er '.transactionReceipts | length | tostring' <<<"$phase_one_record")"
  for ((index = 0; index < receipt_count; index++)); do
    local tx_hash tx_input mined_from mined_to mined_input decoded expected receipt_json receipt_status receipt_hash receipt_to
    local receipt_block receipt_index receipt_timestamp receipt_block_hash receipt_reported_block_hash calldata_hash
    tx_hash="$(jq -er --argjson index "$index" '.transactionReceipts[$index].transactionHash | ascii_downcase' <<<"$phase_one_record")"
    tx_input="$(cast tx "$tx_hash" input --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    mined_from="$(cast tx "$tx_hash" from --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    mined_to="$(cast tx "$tx_hash" to --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    if [ "$(normalize_hex "$mined_from")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ] \
      || [ "$(normalize_hex "$mined_to")" != "$(normalize_hex "$CHALLENGE_REGISTRY_ADDRESS")" ]; then
      echo "Phase-1 ChallengeRegistry transaction $tx_hash has drifted sender or target." >&2
      exit 1
    fi
    decoded="$(cast decode-calldata 'createChallenge(address,(string,bytes32,bytes32,bytes32,bytes32))' "$tx_input" --json)"
    expected="$(jq -c --argjson index "$index" '.entries[$index]' <<<"$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON")"
    if ! jq -e --argjson expected "$expected" '
      type == "array" and length == 2 and (.[1] | type) == "array" and (.[1] | length) == 5
      and (.[0] | ascii_downcase) == ($expected.controller | ascii_downcase)
      and .[1][0] == $expected.metadataURI
      and (.[1][1] | ascii_downcase) == ($expected.metadataHash | ascii_downcase)
      and (.[1][2] | ascii_downcase) == ($expected.sealedArtifactCommitment | ascii_downcase)
      and (.[1][3] | ascii_downcase) == ($expected.evaluatorCommitment | ascii_downcase)
      and (.[1][4] | ascii_downcase) == ($expected.releasePolicyCommitment | ascii_downcase)
    ' <<<"$decoded" >/dev/null; then
      echo "Phase-1 ChallengeRegistry calldata $index no longer proves the reviewed tuple." >&2
      exit 1
    fi
    receipt_json="$(cast receipt "$tx_hash" --confirmations 1 --json --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    receipt_status="$(jq -er '.status' <<<"$receipt_json")"
    receipt_hash="$(jq -er '.transactionHash' <<<"$receipt_json")"
    receipt_to="$(jq -er '.to' <<<"$receipt_json")"
    receipt_reported_block_hash="$(jq -er '.blockHash' <<<"$receipt_json")"
    receipt_block="$(cast to-dec "$(jq -er '.blockNumber' <<<"$receipt_json")")"
    receipt_index="$(cast to-dec "$(jq -er '.transactionIndex' <<<"$receipt_json")")"
    receipt_timestamp="$(rpc_uint_to_decimal "$(cast block "$receipt_block" --field timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
    receipt_block_hash="$(cast block "$receipt_block" --field hash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    calldata_hash="$(cast keccak "$tx_input")"
    if [ "$receipt_status" != "0x1" ] \
      || [ "$(normalize_hex "$receipt_hash")" != "$tx_hash" ] \
      || [ "$(normalize_hex "$receipt_to")" != "$(normalize_hex "$CHALLENGE_REGISTRY_ADDRESS")" ] \
      || [ "$(normalize_hex "$receipt_reported_block_hash")" != "$(normalize_hex "$receipt_block_hash")" ] \
      || ! jq -e \
        --argjson index "$index" \
        --arg blockHash "$receipt_block_hash" \
        --arg calldataHash "$calldata_hash" \
        --argjson blockNumber "$receipt_block" \
        --argjson blockTimestamp "$receipt_timestamp" \
        --argjson transactionIndex "$receipt_index" '
          .transactionReceipts[$index]
          | (.blockHash | ascii_downcase) == ($blockHash | ascii_downcase)
            and (.calldataHash | ascii_downcase) == ($calldataHash | ascii_downcase)
            and .blockNumber == $blockNumber
            and .blockTimestamp == $blockTimestamp
            and .transactionIndex == $transactionIndex
        ' <<<"$phase_one_record" >/dev/null; then
      echo "Phase-1 ChallengeRegistry receipt $tx_hash does not independently match canonical chain evidence." >&2
      exit 1
    fi
  done
}

# Prove the selected RPC supports canonical finalized checkpoints before any
# keystore unlock or irreversible transaction can occur.
pin_state_block finalized
assert_state_block_canonical

if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
  pin_state_block
  pre_common="$(validate_registry_common_state "$OBSERVED_STATE_BLOCK_NUMBER")"
  assert_state_block_canonical
  if [ "$pre_common" != "0 1" ]; then
    echo "Phase 1 requires the exact pristine ChallengeRegistry with next ID 1." >&2
    exit 1
  fi
else
  capture_and_validate_catalog_state draft true
fi
if [ "$BROADCAST" = "true" ] || [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "2" ]; then
  validate_release_history_prestate
fi

if [ "$BROADCAST" = "true" ]; then
  check_release_provenance
  if [ "$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")" = "0" ]; then
    echo "DEPLOYMENT_OPERATOR has no Base Sepolia ETH for ChallengeRegistry governance gas." >&2
    exit 1
  fi
fi

echo "== ChallengeRegistry exact genesis phase $CHALLENGE_REGISTRY_RELEASE_PHASE =="
echo "Chain ID:          $live_chain_id"
echo "Keystore account:  dev"
echo "Operator:          $DEPLOYMENT_OPERATOR"
echo "ChallengeRegistry: $CHALLENGE_REGISTRY_ADDRESS"
echo "Genesis entries:   $catalog_count"
echo "Broadcast:         $BROADCAST"

cd "$CONTRACTS_DIR"
forge build --sizes
forge test --threads 1 --match-path test/ConfigureChallengeRegistryRelease.t.sol

echo
echo "== Dry run =="
forge script script/ConfigureChallengeRegistryRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

if [ "$BROADCAST" != "true" ]; then
  echo "Dry run complete; no chain state changed."
  exit 0
fi

operator_policy_acquire_release_ceremony_lock challenge_registry_release
check_release_provenance
validate_existing_deployment_ledger
if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
  pin_state_block
  [ "$(validate_registry_common_state "$OBSERVED_STATE_BLOCK_NUMBER")" = "0 1" ] || {
    echo "ChallengeRegistry pristine state changed after dry run." >&2
    exit 1
  }
  assert_state_block_canonical
else
  capture_and_validate_catalog_state draft true
fi
validate_release_history_prestate
ledger_blob_before_broadcast="$(deployment_ledger_blob)"

unlocked_signer="$(cast wallet address --account dev)"
if [ "$(normalize_hex "$unlocked_signer")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ]; then
  echo "The unlocked dev keystore does not match DEPLOYMENT_OPERATOR." >&2
  exit 1
fi
check_release_provenance
revalidate_release_authority_and_catalog
validate_existing_deployment_ledger
if [ "$(deployment_ledger_blob)" != "$ledger_blob_before_broadcast" ]; then
  echo "Deployment ledger changed while the ChallengeRegistry keystore was unlocking." >&2
  exit 1
fi

# Recheck the complete phase pre-state immediately before the first irreversible
# transaction. Any concurrent catalog, owner, pause, or version drift aborts.
if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
  pin_state_block
  [ "$(validate_registry_common_state "$OBSERVED_STATE_BLOCK_NUMBER")" = "0 1" ] || {
    echo "ChallengeRegistry pristine state changed after dry run." >&2
    exit 1
  }
  assert_state_block_canonical
else
  capture_and_validate_catalog_state draft true
fi
validate_release_history_prestate
if [ "$(deployment_ledger_blob)" != "$ledger_blob_before_broadcast" ]; then
  echo "Deployment ledger changed during the immediate ChallengeRegistry pre-broadcast validation." >&2
  exit 1
fi
revalidate_release_authority_and_catalog
check_release_provenance

echo
echo "== Broadcast exact ChallengeRegistry genesis phase =="
forge script script/ConfigureChallengeRegistryRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --account dev \
  --broadcast \
  --slow

check_release_provenance

if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
  ledger_status=deployed_exact_arena_genesis_pending_version_review
  ledger_policy_state=arena_genesis_fail_closed_pending_two_day_version_review
  expected_tx_count="$catalog_count"
else
  ledger_status=deployed_exact_arena_genesis_frozen_open
  ledger_policy_state=arena_genesis_exact_version_one_catalog_frozen_open
  expected_tx_count=$((catalog_count * 2))
fi

RUN_PATH="$FOUNDRY_BROADCAST/ConfigureChallengeRegistryRelease.s.sol/$CHAIN_ID/run-latest.json"
if [ ! -f "$RUN_PATH" ] || [ -L "$RUN_PATH" ]; then
  echo "Missing non-symlink Forge broadcast receipt at $RUN_PATH." >&2
  exit 1
fi
run_parent="$(dirname "$RUN_PATH")"
if [ ! -d "$run_parent" ] || [ -L "$run_parent" ] \
  || [ "$(cd "$run_parent" && pwd -P)" != "$run_parent" ]; then
  echo "Forge ChallengeRegistry broadcast receipt has a noncanonical or symlinked parent path." >&2
  exit 1
fi
if run_link_count="$(stat -f '%l' "$RUN_PATH" 2>/dev/null)"; then
  :
else
  run_link_count="$(stat -c '%h' "$RUN_PATH")"
fi
if [ "$run_link_count" != "1" ]; then
  echo "Forge ChallengeRegistry broadcast receipt must not be a hard link." >&2
  exit 1
fi
if run_size="$(stat -f '%z' "$RUN_PATH" 2>/dev/null)"; then
  :
else
  run_size="$(stat -c '%s' "$RUN_PATH")"
fi
validate_safe_json_uint run_size "$run_size"
if [ "$run_size" = "0" ] || [ "$run_size" -gt 4194304 ]; then
  echo "Forge ChallengeRegistry broadcast receipt exceeds the bounded evidence size." >&2
  exit 1
fi
run_blob_before="$(git hash-object --no-filters "$RUN_PATH")"
if ! jq -e \
  --arg registry "$CHALLENGE_REGISTRY_ADDRESS" \
  --arg operator "$DEPLOYMENT_OPERATOR" \
  --argjson expected "$expected_tx_count" '
    (.transactions // null) as $transactions
    | ($transactions | type) == "array" and ($transactions | length) == $expected
    and ([$transactions[]
      | .transactionType == "CALL"
        and (.hash | type == "string" and test("^0x[0-9a-fA-F]{64}$") and ascii_downcase != ("0x" + ("0" * 64)))
        and ((.transaction.to // "") | ascii_downcase) == ($registry | ascii_downcase)
        and ((.transaction.from // "") | ascii_downcase) == ($operator | ascii_downcase)
        and .transaction.chainId == "0x14a34"
        and (.transaction.input | type == "string" and test("^0x[0-9a-fA-F]+$"))
    ] | all)
    and ([$transactions[].hash | ascii_downcase] | unique | length) == $expected
  ' "$RUN_PATH" >/dev/null; then
  echo "Forge broadcast artifact does not contain the exact unique ChallengeRegistry transaction set." >&2
  exit 1
fi

transaction_receipts='[]'
highest_receipt_block=0
for ((index = 0; index < expected_tx_count; index++)); do
  tx_hash="$(jq -er --argjson index "$index" '.transactions[$index].hash | ascii_downcase' "$RUN_PATH")"
  tx_input="$(jq -er --argjson index "$index" '.transactions[$index].transaction.input | ascii_downcase' "$RUN_PATH")"
  if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
    challenge_id=$((index + 1))
    function_name=createChallenge
    decoded="$(cast decode-calldata 'createChallenge(address,(string,bytes32,bytes32,bytes32,bytes32))' "$tx_input" --json)"
    expected="$(jq -c --argjson index "$index" '.entries[$index]' <<<"$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON")"
    if ! jq -e --argjson expected "$expected" '
      type == "array" and length == 2 and (.[1] | type) == "array" and (.[1] | length) == 5
      and (.[0] | ascii_downcase) == ($expected.controller | ascii_downcase)
      and .[1][0] == $expected.metadataURI
      and (.[1][1] | ascii_downcase) == ($expected.metadataHash | ascii_downcase)
      and (.[1][2] | ascii_downcase) == ($expected.sealedArtifactCommitment | ascii_downcase)
      and (.[1][3] | ascii_downcase) == ($expected.evaluatorCommitment | ascii_downcase)
      and (.[1][4] | ascii_downcase) == ($expected.releasePolicyCommitment | ascii_downcase)
    ' <<<"$decoded" >/dev/null; then
      echo "ChallengeRegistry create calldata $index does not match the reviewed catalog." >&2
      exit 1
    fi
  else
    challenge_id=$((index / 2 + 1))
    if [ $((index % 2)) -eq 0 ]; then
      function_name=freezeChallengeConfiguration
      decoded="$(cast decode-calldata 'freezeChallengeConfiguration(uint256)' "$tx_input" --json)"
      jq -e --argjson challengeId "$challenge_id" 'length == 1 and .[0] == $challengeId' <<<"$decoded" >/dev/null || {
        echo "ChallengeRegistry freeze calldata $index is out of order." >&2
        exit 1
      }
    else
      function_name=setLifecycleOpen
      decoded="$(cast decode-calldata 'setLifecycle(uint256,uint8)' "$tx_input" --json)"
      jq -e --argjson challengeId "$challenge_id" 'length == 2 and .[0] == $challengeId and .[1] == 1' <<<"$decoded" >/dev/null || {
        echo "ChallengeRegistry lifecycle calldata $index is not the exact Open transition." >&2
        exit 1
      }
    fi
  fi

  mined_from="$(cast tx "$tx_hash" from --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  mined_to="$(cast tx "$tx_hash" to --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  mined_input="$(cast tx "$tx_hash" input --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  if [ "$(normalize_hex "$mined_from")" != "$(normalize_hex "$DEPLOYMENT_OPERATOR")" ] \
    || [ "$(normalize_hex "$mined_to")" != "$(normalize_hex "$CHALLENGE_REGISTRY_ADDRESS")" ] \
    || [ "$(normalize_hex "$mined_input")" != "$tx_input" ]; then
    echo "Mined ChallengeRegistry transaction $tx_hash does not match the Forge artifact." >&2
    exit 1
  fi
  receipt_json="$(cast receipt "$tx_hash" --confirmations 1 --json --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  receipt_status="$(jq -er '.status' <<<"$receipt_json")"
  receipt_hash="$(jq -er '.transactionHash' <<<"$receipt_json")"
  receipt_to="$(jq -er '.to' <<<"$receipt_json")"
  receipt_block_hash="$(jq -er '.blockHash' <<<"$receipt_json")"
  receipt_block="$(cast to-dec "$(jq -er '.blockNumber' <<<"$receipt_json")")"
  receipt_index="$(cast to-dec "$(jq -er '.transactionIndex' <<<"$receipt_json")")"
  if [ "$receipt_status" != "0x1" ]; then
    echo "ChallengeRegistry transaction $tx_hash was not accepted on-chain." >&2
    exit 1
  fi
  if [ "$(normalize_hex "$receipt_hash")" != "$tx_hash" ] \
    || [ "$(normalize_hex "$receipt_to")" != "$(normalize_hex "$CHALLENGE_REGISTRY_ADDRESS")" ]; then
    echo "ChallengeRegistry receipt $tx_hash does not target the reviewed registry." >&2
    exit 1
  fi
  validate_safe_json_uint receipt_block "$receipt_block"
  validate_safe_json_uint receipt_index "$receipt_index"
  validate_bytes32 receipt_block_hash "$receipt_block_hash"
  receipt_timestamp="$(rpc_uint_to_decimal "$(cast block "$receipt_block" --field timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
  canonical_receipt_block_hash="$(cast block "$receipt_block" --field hash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  validate_safe_json_uint receipt_timestamp "$receipt_timestamp"
  if [ "$receipt_block" = "0" ] || [ "$receipt_timestamp" = "0" ] \
    || [ "$(normalize_hex "$canonical_receipt_block_hash")" != "$(normalize_hex "$receipt_block_hash")" ]; then
    echo "ChallengeRegistry receipt $tx_hash has invalid block provenance." >&2
    exit 1
  fi
  if [ "$receipt_block" -gt "$highest_receipt_block" ]; then
    highest_receipt_block="$receipt_block"
  fi
  calldata_hash="$(cast keccak "$tx_input")"
  validate_bytes32 calldata_hash "$calldata_hash"
  transaction_receipts="$(jq -c \
    --argjson current "$transaction_receipts" \
    --arg transactionHash "$tx_hash" \
    --arg calldataHash "$calldata_hash" \
    --arg blockHash "$receipt_block_hash" \
    --arg function "$function_name" \
    --argjson challengeId "$challenge_id" \
    --argjson blockNumber "$receipt_block" \
    --argjson blockTimestamp "$receipt_timestamp" \
    --argjson transactionIndex "$receipt_index" \
    '$current + [{transactionHash: $transactionHash, calldataHash: $calldataHash, function: $function, challengeId: $challengeId, blockHash: $blockHash, blockNumber: $blockNumber, blockTimestamp: $blockTimestamp, transactionIndex: $transactionIndex}]' <<<"{}")"
done

if [ "$(git hash-object --no-filters "$RUN_PATH")" != "$run_blob_before" ]; then
  echo "Forge ChallengeRegistry broadcast receipt changed during evidence validation." >&2
  exit 1
fi

wait_for_finalized_receipts "$highest_receipt_block"
assert_receipt_blocks_canonical
if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
  capture_and_validate_catalog_state draft false finalized
else
  capture_and_validate_catalog_state open false finalized
fi

validate_existing_deployment_ledger
if [ "$(deployment_ledger_blob)" != "$ledger_blob_before_broadcast" ]; then
  echo "Deployment ledger changed while the ChallengeRegistry release was broadcasting; refusing to overwrite it." >&2
  exit 1
fi
if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
  capture_and_validate_catalog_state draft false finalized
else
  capture_and_validate_catalog_state open false finalized
fi
FINALIZED_CATALOG_JSON="$OBSERVED_CATALOG_JSON"
FINALIZED_STATE_BLOCK_NUMBER="$OBSERVED_STATE_BLOCK_NUMBER"
FINALIZED_STATE_BLOCK_HASH="$OBSERVED_STATE_BLOCK_HASH"
FINALIZED_STATE_BLOCK_TIMESTAMP="$OBSERVED_STATE_BLOCK_TIMESTAMP"
if [ "$CHALLENGE_REGISTRY_RELEASE_PHASE" = "1" ]; then
  capture_and_validate_catalog_state draft false latest
else
  capture_and_validate_catalog_state open false latest
fi
LATEST_STATE_BLOCK_NUMBER="$OBSERVED_STATE_BLOCK_NUMBER"
LATEST_STATE_BLOCK_HASH="$OBSERVED_STATE_BLOCK_HASH"
LATEST_STATE_BLOCK_TIMESTAMP="$OBSERVED_STATE_BLOCK_TIMESTAMP"
if ! jq -e --argjson finalized "$FINALIZED_CATALOG_JSON" --argjson latest "$OBSERVED_CATALOG_JSON" \
  '$finalized == $latest' <<<"{}" >/dev/null; then
  echo "Latest ChallengeRegistry state differs from the exact finalized poststate." >&2
  exit 1
fi
OBSERVED_CATALOG_JSON="$FINALIZED_CATALOG_JSON"
OBSERVED_STATE_BLOCK_NUMBER="$FINALIZED_STATE_BLOCK_NUMBER"
OBSERVED_STATE_BLOCK_HASH="$FINALIZED_STATE_BLOCK_HASH"
OBSERVED_STATE_BLOCK_TIMESTAMP="$FINALIZED_STATE_BLOCK_TIMESTAMP"
recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
manifest_dir="$(dirname "$MANIFEST_PATH")"
manifest_base="$(basename "$MANIFEST_PATH")"
CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH="$(mktemp "$manifest_dir/.${manifest_base}.challenge-registry-release.XXXXXX")"

jq \
  --argjson chainId "$CHAIN_ID" \
  --arg registryAddress "$CHALLENGE_REGISTRY_ADDRESS" \
  --arg runtimeCodeHash "$CHALLENGE_REGISTRY_RUNTIME_CODE_HASH" \
  --arg operator "$DEPLOYMENT_OPERATOR" \
  --arg sourceCommit "$RELEASE_SHA" \
  --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --arg catalogProjectionSha256 "$catalog_projection_sha256" \
  --argjson phase "$CHALLENGE_REGISTRY_RELEASE_PHASE" \
  --arg recordedAt "$recorded_at" \
  --arg status "$ledger_status" \
  --arg policyState "$ledger_policy_state" \
  --argjson stateBlockNumber "$OBSERVED_STATE_BLOCK_NUMBER" \
  --arg stateBlockHash "$OBSERVED_STATE_BLOCK_HASH" \
  --argjson stateBlockTimestamp "$OBSERVED_STATE_BLOCK_TIMESTAMP" \
  --argjson latestCheckBlockNumber "$LATEST_STATE_BLOCK_NUMBER" \
  --arg latestCheckBlockHash "$LATEST_STATE_BLOCK_HASH" \
  --argjson latestCheckBlockTimestamp "$LATEST_STATE_BLOCK_TIMESTAMP" \
  --argjson catalog "$CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON" \
  --argjson observedCatalog "$OBSERVED_CATALOG_JSON" \
  --argjson transactionReceipts "$transaction_receipts" \
  -f "$MANIFEST_FILTER" "$MANIFEST_PATH" > "$CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH"

if ! jq -e 'type == "object"' "$CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH" >/dev/null; then
  echo "ChallengeRegistry release ledger update did not produce one valid JSON object." >&2
  exit 1
fi
if [ "$(deployment_ledger_blob)" != "$ledger_blob_before_broadcast" ]; then
  echo "Deployment ledger changed during ChallengeRegistry evidence rendering; refusing to overwrite it." >&2
  exit 1
fi
assert_state_block_canonical
assert_named_block_canonical "$LATEST_STATE_BLOCK_NUMBER" "$LATEST_STATE_BLOCK_HASH" "Latest checked ChallengeRegistry state"
operator_policy_durably_replace_release_ledger \
  "$CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH" \
  "$MANIFEST_PATH"
rm -f -- "$CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH"
CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH=""
operator_policy_release_release_ceremony_lock

echo "ChallengeRegistry release phase $CHALLENGE_REGISTRY_RELEASE_PHASE completed with exact post-state and append-only ledger evidence."
