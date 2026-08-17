#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

# Read-only, dual-provider proof for the exact ERC-20 asset admitted by the
# ComputeCreditVault release. The four COMPUTE_VAULT_ERC20_ASSET_* values must
# first be derived from the code-owned, semantically validated final-authority
# projection by configure-compute-release.sh. This helper never reads an
# authority artifact directly and never infers a value from the live chain.

CHAIN_ID=84532
CANONICAL_BASE_SEPOLIA_USDC=0x036cbd53842c5426634e7929541ec2318f3dcf7e
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
MAX_RPC_RESPONSE_BYTES=2097152
MAX_SAFE_JSON_INTEGER=9007199254740991
DECIMALS_SELECTOR=0x313ce567
SYMBOL_SELECTOR=0x95d89b41

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; canonical USDC authority is never inferred." >&2
    exit 1
  fi
}

normalize_hex() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

validate_address() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || [ "$(normalize_hex "$value")" = "0x0000000000000000000000000000000000000000" ]; then
    echo "$name must be a nonzero Ethereum address." >&2
    exit 1
  fi
}

validate_bytes32() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] \
    || [ "$(normalize_hex "$value")" = "$ZERO_BYTES32" ]; then
    echo "$name must be a nonzero bytes32 value." >&2
    exit 1
  fi
}

validate_safe_uint() {
  local name="$1"
  local value="$2"
  local LC_ALL=C
  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ ]]; then
    echo "$name must be a canonical unsigned decimal integer." >&2
    exit 1
  fi
  if [ "${#value}" -gt "${#MAX_SAFE_JSON_INTEGER}" ] \
    || { [ "${#value}" -eq "${#MAX_SAFE_JSON_INTEGER}" ] && [[ "$value" > "$MAX_SAFE_JSON_INTEGER" ]]; }; then
    echo "$name exceeds the exact JSON integer range." >&2
    exit 1
  fi
}

validate_rpc_authority_pair() {
  local primary="$1"
  local secondary="$2"
  if ! node --input-type=module - "$primary" "$secondary" <<'NODE'
const endpoints = process.argv.slice(2);
function canonicalEndpoint(value) {
  if (!value || value !== value.trim() || Buffer.byteLength(value, "utf8") > 4_096) {
    throw new Error("invalid endpoint");
  }
  const endpoint = new URL(value);
  if (endpoint.protocol !== "https:" || !endpoint.hostname
    || endpoint.username || endpoint.password || endpoint.hash) {
    throw new Error("invalid endpoint");
  }
  return endpoint;
}
try {
  const primary = canonicalEndpoint(endpoints[0]);
  const secondary = canonicalEndpoint(endpoints[1]);
  if (primary.href === secondary.href
    || primary.origin.toLowerCase() === secondary.origin.toLowerCase()) {
    process.exitCode = 1;
  }
} catch {
  process.exitCode = 1;
}
NODE
  then
    echo "Primary and secondary Base Sepolia RPCs must use distinct HTTPS scheme/host/port origins without URL userinfo." >&2
    exit 1
  fi
}

rpc_result() {
  local provider_label="$1"
  local rpc_url="$2"
  local method="$3"
  shift 3
  local response
  if ! response="$(cast rpc --rpc-url "$rpc_url" "$method" "$@" 2>/dev/null)"; then
    echo "$provider_label Base Sepolia RPC rejected $method at the required finalized numeric block." >&2
    return 1
  fi
  if [ -z "$response" ] || [ "${#response}" -gt "$MAX_RPC_RESPONSE_BYTES" ]; then
    echo "$provider_label Base Sepolia RPC returned an empty or oversized $method response." >&2
    return 1
  fi
  printf '%s' "$response"
}

read_chain_id() {
  local provider_label="$1"
  local rpc_url="$2"
  local response quantity decimal
  if ! response="$(rpc_result "$provider_label" "$rpc_url" eth_chainId)"; then
    return 1
  fi
  if ! quantity="$(jq -er 'select(type == "string" and test("^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$"))' <<<"$response")"; then
    echo "$provider_label Base Sepolia RPC returned a malformed eth_chainId result." >&2
    return 1
  fi
  if ! decimal="$(cast to-dec "$quantity" 2>/dev/null)"; then
    echo "$provider_label Base Sepolia RPC returned an undecodable eth_chainId result." >&2
    return 1
  fi
  validate_safe_uint "$provider_label chain ID" "$decimal"
  printf '%s' "$decimal"
}

read_block_identity() {
  local provider_label="$1"
  local rpc_url="$2"
  local block_tag="$3"
  local response identity decimal
  if ! response="$(rpc_result "$provider_label" "$rpc_url" eth_getBlockByNumber "$block_tag" false)"; then
    return 1
  fi
  if ! identity="$(jq -cer '
    select(type == "object")
    | {
        number: (.number | ascii_downcase
          | select(test("^0x[1-9a-f][0-9a-f]*$"))),
        hash: (.hash | ascii_downcase
          | select(test("^0x[0-9a-f]{64}$") and . != ("0x" + ("0" * 64))))
      }
  ' <<<"$response")"; then
    echo "$provider_label Base Sepolia RPC returned a malformed finalized block identity." >&2
    return 1
  fi
  if ! decimal="$(cast to-dec "$(jq -r '.number' <<<"$identity")" 2>/dev/null)"; then
    echo "$provider_label Base Sepolia RPC returned an undecodable finalized block number." >&2
    return 1
  fi
  validate_safe_uint "$provider_label finalized block number" "$decimal"
  jq -cn \
    --arg numberHex "$(jq -r '.number' <<<"$identity")" \
    --argjson number "$decimal" \
    --arg hash "$(jq -r '.hash' <<<"$identity")" \
    '{numberHex:$numberHex,number:$number,hash:$hash}'
}

read_code() {
  local provider_label="$1"
  local rpc_url="$2"
  local asset="$3"
  local block_hex="$4"
  local response code
  if ! response="$(rpc_result "$provider_label" "$rpc_url" eth_getCode "$asset" "$block_hex")"; then
    return 1
  fi
  if ! code="$(jq -er '
    select(type == "string" and test("^0x([0-9a-fA-F]{2})+$"))
    | ascii_downcase
  ' <<<"$response")"; then
    echo "$provider_label Base Sepolia RPC returned malformed or empty USDC runtime code." >&2
    return 1
  fi
  if [ "${#code}" -gt "$MAX_RPC_RESPONSE_BYTES" ]; then
    echo "$provider_label Base Sepolia USDC runtime code exceeds the bounded release probe." >&2
    return 1
  fi
  printf '%s' "$code"
}

read_call_result() {
  local provider_label="$1"
  local rpc_url="$2"
  local asset="$3"
  local selector="$4"
  local block_hex="$5"
  local call_object response result
  call_object="$(jq -cn --arg to "$asset" --arg data "$selector" '{to:$to,data:$data}')"
  if ! response="$(rpc_result "$provider_label" "$rpc_url" eth_call "$call_object" "$block_hex")"; then
    return 1
  fi
  if ! result="$(jq -er 'select(type == "string" and test("^0x([0-9a-fA-F]{2})+$"))' <<<"$response")"; then
    echo "$provider_label Base Sepolia RPC returned a malformed USDC eth_call result." >&2
    return 1
  fi
  if [ "${#result}" -gt 4096 ]; then
    echo "$provider_label Base Sepolia USDC metadata result exceeds the bounded release probe." >&2
    return 1
  fi
  printf '%s' "$result"
}

for required in cast jq node; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required for the canonical USDC release proof." >&2
    exit 1
  fi
done

for name in \
  BASE_SEPOLIA_RPC_URL \
  BASE_SEPOLIA_SECONDARY_RPC_URL \
  COMPUTE_VAULT_ERC20_ASSET_ADDRESS \
  COMPUTE_VAULT_ERC20_ASSET_CODE_HASH \
  COMPUTE_VAULT_ERC20_ASSET_SYMBOL \
  COMPUTE_VAULT_ERC20_ASSET_DECIMALS; do
  require_env "$name"
done

validate_rpc_authority_pair "$BASE_SEPOLIA_RPC_URL" "$BASE_SEPOLIA_SECONDARY_RPC_URL"
validate_address COMPUTE_VAULT_ERC20_ASSET_ADDRESS "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS"
validate_bytes32 COMPUTE_VAULT_ERC20_ASSET_CODE_HASH "$COMPUTE_VAULT_ERC20_ASSET_CODE_HASH"
if [ "$(normalize_hex "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS")" != "$CANONICAL_BASE_SEPOLIA_USDC" ]; then
  echo "The reviewed Compute ERC-20 asset is not canonical Base Sepolia USDC." >&2
  exit 1
fi
if [ "$COMPUTE_VAULT_ERC20_ASSET_SYMBOL" != "USDC" ] \
  || [ "$COMPUTE_VAULT_ERC20_ASSET_DECIMALS" != "6" ]; then
  echo "The reviewed Compute ERC-20 metadata must be exact USDC with 6 decimals." >&2
  exit 1
fi

primary_chain_id="$(read_chain_id primary "$BASE_SEPOLIA_RPC_URL")"
secondary_chain_id="$(read_chain_id secondary "$BASE_SEPOLIA_SECONDARY_RPC_URL")"
if [ "$primary_chain_id" != "$CHAIN_ID" ] || [ "$secondary_chain_id" != "$CHAIN_ID" ]; then
  echo "Both independent RPCs must report Base Sepolia chain ID 84532." >&2
  exit 1
fi

primary_finalized="$(read_block_identity primary "$BASE_SEPOLIA_RPC_URL" finalized)"
secondary_finalized="$(read_block_identity secondary "$BASE_SEPOLIA_SECONDARY_RPC_URL" finalized)"
if [ "$primary_finalized" != "$secondary_finalized" ]; then
  echo "Independent Base Sepolia RPCs do not agree on one finalized block number and hash." >&2
  exit 1
fi
finalized_block_hex="$(jq -r '.numberHex' <<<"$primary_finalized")"
finalized_block_number="$(jq -r '.number' <<<"$primary_finalized")"
finalized_block_hash="$(jq -r '.hash' <<<"$primary_finalized")"

primary_code="$(read_code primary "$BASE_SEPOLIA_RPC_URL" "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS" "$finalized_block_hex")"
secondary_code="$(read_code secondary "$BASE_SEPOLIA_SECONDARY_RPC_URL" "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS" "$finalized_block_hex")"
if [ "$primary_code" != "$secondary_code" ]; then
  echo "Independent Base Sepolia RPCs returned different USDC runtime code at the agreed finalized block." >&2
  exit 1
fi
live_code_hash="$(normalize_hex "$(cast keccak "$primary_code")")"
validate_bytes32 "live USDC runtime code hash" "$live_code_hash"
if [ "$live_code_hash" != "$(normalize_hex "$COMPUTE_VAULT_ERC20_ASSET_CODE_HASH")" ]; then
  echo "Canonical Base Sepolia USDC runtime code does not match the signed final authority." >&2
  exit 1
fi

primary_decimals_raw="$(read_call_result primary "$BASE_SEPOLIA_RPC_URL" "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS" "$DECIMALS_SELECTOR" "$finalized_block_hex")"
secondary_decimals_raw="$(read_call_result secondary "$BASE_SEPOLIA_SECONDARY_RPC_URL" "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS" "$DECIMALS_SELECTOR" "$finalized_block_hex")"
primary_symbol_raw="$(read_call_result primary "$BASE_SEPOLIA_RPC_URL" "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS" "$SYMBOL_SELECTOR" "$finalized_block_hex")"
secondary_symbol_raw="$(read_call_result secondary "$BASE_SEPOLIA_SECONDARY_RPC_URL" "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS" "$SYMBOL_SELECTOR" "$finalized_block_hex")"
if [ "$(normalize_hex "$primary_decimals_raw")" != "$(normalize_hex "$secondary_decimals_raw")" ] \
  || [ "$(normalize_hex "$primary_symbol_raw")" != "$(normalize_hex "$secondary_symbol_raw")" ]; then
  echo "Independent Base Sepolia RPCs returned divergent USDC metadata at the agreed finalized block." >&2
  exit 1
fi
if ! live_decimals="$(cast abi-decode 'decimals()(uint8)' "$primary_decimals_raw")" \
  || ! validate_safe_uint "live USDC decimals" "$live_decimals"; then
  echo "Canonical Base Sepolia USDC decimals are not valid ABI data." >&2
  exit 1
fi
if ! live_symbol_json="$(cast abi-decode 'symbol()(string)' "$primary_symbol_raw")" \
  || ! live_symbol="$(jq -er 'select(type == "string" and length > 0 and length <= 32)' <<<"$live_symbol_json")"; then
  echo "Canonical Base Sepolia USDC symbol is not valid bounded ABI data." >&2
  exit 1
fi
if [ "$live_decimals" != "$COMPUTE_VAULT_ERC20_ASSET_DECIMALS" ] \
  || [ "$live_symbol" != "$COMPUTE_VAULT_ERC20_ASSET_SYMBOL" ]; then
  echo "Canonical Base Sepolia USDC metadata does not match the signed final authority." >&2
  exit 1
fi

# Re-read the exact numeric block header after code and metadata reads. This
# fails closed if either provider cannot serve historical state or changes its
# view of the supposedly finalized block during the proof.
primary_numeric_block="$(read_block_identity primary "$BASE_SEPOLIA_RPC_URL" "$finalized_block_hex")"
secondary_numeric_block="$(read_block_identity secondary "$BASE_SEPOLIA_SECONDARY_RPC_URL" "$finalized_block_hex")"
if [ "$primary_numeric_block" != "$primary_finalized" ] \
  || [ "$secondary_numeric_block" != "$primary_finalized" ]; then
  echo "Independent Base Sepolia RPCs did not preserve the agreed finalized numeric block identity." >&2
  exit 1
fi

jq -cn \
  --arg schema "dnai.base-sepolia-usdc-finalized-authority.v1" \
  --argjson chainId "$CHAIN_ID" \
  --argjson finalizedBlockNumber "$finalized_block_number" \
  --arg finalizedBlockHash "$finalized_block_hash" \
  --arg assetAddress "$(normalize_hex "$COMPUTE_VAULT_ERC20_ASSET_ADDRESS")" \
  --arg runtimeCodeHash "$live_code_hash" \
  --arg symbol "$live_symbol" \
  --argjson decimals "$live_decimals" \
  --arg proof "two_distinct_https_rpcs_exact_finalized_numeric_block_eth_getCode_and_eth_call_agreement" \
  '{
    schema:$schema,
    chainId:$chainId,
    finalizedBlockNumber:$finalizedBlockNumber,
    finalizedBlockHash:$finalizedBlockHash,
    assetAddress:$assetAddress,
    runtimeCodeHash:$runtimeCodeHash,
    symbol:$symbol,
    decimals:$decimals,
    proof:$proof
  }'
