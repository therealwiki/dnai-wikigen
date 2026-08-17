#!/usr/bin/env bash
set -euo pipefail

# Rehearse the complete fresh-suite release against an already-running local
# Anvil node whose chain id is shaped like Base Sepolia. This helper never reads
# the repository .env, never writes the production deployment manifest, and
# signs every transaction through Anvil's unlocked JSON-RPC accounts.

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$CONTRACTS_DIR/../../.." && pwd)"
MANIFEST_FILTER="$SCRIPT_DIR/merge-base-sepolia-suite-manifest.jq"
CHAIN_ID=84532
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
ZERO_EVALUATOR_POLICIES_ABI="0x$(printf '0%.0s' {1..192})"
RPC_URL="${ANVIL_RPC_URL:-http://127.0.0.1:18545}"
DEPLOYMENT_RECEIPTS='{}'
BROADCAST_TRANSACTIONS='[]'
BROADCAST_TRANSACTIONS_SHA256=""

fail() {
  echo "Local release rehearsal failed: $*" >&2
  exit 1
}

normalize_address() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

validate_address() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]] || [ "$(normalize_address "$value")" = "$ZERO_ADDRESS" ]; then
    fail "$label is not a nonzero Ethereum address"
  fi
}

validate_bytes32() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] || [ "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" = "$ZERO_BYTES32" ]; then
    fail "$label is not a nonzero bytes32 value"
  fi
}

validate_sha256() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    fail "$label is not a canonical sha256 digest"
  fi
}

normalize_quantity() {
  local label="$1"
  local value="$2"
  if [[ "$value" =~ ^0x[0-9a-fA-F]+$ ]]; then
    cast to-dec "$value" || fail "$label could not be converted from hex"
  elif [[ "$value" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$value"
  else
    fail "$label is not an Ethereum quantity"
  fi
}

validate_transaction_input() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x([0-9a-f][0-9a-f])+$ ]]; then
    fail "$label must be nonempty canonical lowercase byte-aligned hex"
  fi
}

creation_input() {
  local contract_name="$1"
  local constructor_signature="$2"
  shift 2
  local creation_code
  local constructor_args="0x"
  local normalized

  creation_code="$(forge inspect "$contract_name" bytecode | tr '[:upper:]' '[:lower:]')" \
    || fail "$contract_name creation bytecode could not be inspected"
  if [ -n "$constructor_signature" ]; then
    constructor_args="$(cast abi-encode "$constructor_signature" "$@" | tr '[:upper:]' '[:lower:]')" \
      || fail "$contract_name constructor arguments could not be encoded"
  fi
  normalized="0x${creation_code#0x}${constructor_args#0x}"
  validate_transaction_input "$contract_name reconstructed creation input" "$normalized"
  printf '%s' "$normalized"
}

transaction_input_sha256() {
  local value="$1"
  validate_transaction_input "transaction input" "$value"
  printf '%s' "$value" | node -e '
    const fs = require("node:fs");
    const crypto = require("node:crypto");
    const value = fs.readFileSync(0, "utf8");
    if (!/^0x(?:[0-9a-f]{2})+$/.test(value)) process.exit(2);
    process.stdout.write(`sha256:${crypto.createHash("sha256").update(Buffer.from(value.slice(2), "hex")).digest("hex")}`);
  '
}

assert_equal() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [ "$actual" != "$expected" ]; then
    fail "$label mismatch: expected $expected, received $actual"
  fi
}

assert_address_equal() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  assert_equal "$label" "$(normalize_address "$expected")" "$(normalize_address "$actual")"
}

read_uint() {
  cast call "$1" "$2" "${@:3}" --rpc-url "$RPC_URL" | awk '{print $1}'
}

block_timestamp() {
  local value
  value="$(cast block latest --rpc-url "$RPC_URL" --json | jq -r '.timestamp')"
  if [[ "$value" == 0x* ]]; then
    cast to-dec "$value"
  else
    printf '%s\n' "$value"
  fi
}

send_tx() {
  local label="$1"
  local sender="$2"
  shift 2
  local receipt="$EVIDENCE_DIR/receipts/$label.json"

  cast send "$@" \
    --rpc-url "$RPC_URL" \
    --from "$sender" \
    --unlocked \
    --json > "$receipt"

  if ! jq -e '(.status == "0x1") or (.status == "1") or (.status == 1)' "$receipt" >/dev/null; then
    fail "$label transaction did not succeed"
  fi
  jq -r '.transactionHash' "$receipt"
}

receipt_block() {
  local label="$1"
  local value
  value="$(jq -r '.blockNumber' "$EVIDENCE_DIR/receipts/$label.json")"
  if [[ "$value" == 0x* ]]; then
    cast to-dec "$value"
  else
    printf '%s\n' "$value"
  fi
}

contract_address() {
  local contract_name="$1"
  jq -er --arg name "$contract_name" '
    [.transactions[] | select(.transactionType == "CREATE" and .contractName == $name)]
    | if length == 1 then .[0].contractAddress
      else error("expected exactly one CREATE transaction for " + $name)
      end
    | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))
    | ascii_downcase
  ' "$RUN_PATH"
}

contract_tx() {
  local contract_name="$1"
  jq -er --arg name "$contract_name" '
    [.transactions[] | select(.transactionType == "CREATE" and .contractName == $name)]
    | if length == 1 then .[0].hash
      else error("expected exactly one CREATE transaction for " + $name)
      end
    | select(type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    | ascii_downcase
  ' "$RUN_PATH"
}

collect_deployment_receipt() {
  local ledger_key="$1"
  local transaction_hash="$2"
  local deployed_address="$3"
  local receipt_json
  local receipt_transaction_hash
  local receipt_from
  local receipt_status
  local receipt_contract_address
  local receipt_block_raw
  local receipt_block
  local receipt_block_hash

  receipt_json="$(cast receipt "$transaction_hash" --rpc-url "$RPC_URL" --json)" \
    || fail "$ledger_key deployment receipt could not be read"
  [ "${#receipt_json}" -le 524288 ] \
    || fail "$ledger_key deployment receipt exceeded the evidence bound"
  receipt_transaction_hash="$(jq -er '
    .transactionHash
    | select(type == "string" and test("^0x[0-9a-fA-F]{64}$"))
  ' <<<"$receipt_json")" || fail "$ledger_key receipt transaction hash is invalid"
  assert_equal \
    "$ledger_key receipt transaction hash" \
    "$(printf '%s' "$transaction_hash" | tr '[:upper:]' '[:lower:]')" \
    "$(printf '%s' "$receipt_transaction_hash" | tr '[:upper:]' '[:lower:]')"
  receipt_from="$(jq -er '
    .from | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))
  ' <<<"$receipt_json")" || fail "$ledger_key receipt sender is invalid"
  assert_address_equal "$ledger_key receipt sender" "$DEPLOYMENT_OPERATOR" "$receipt_from"
  receipt_status="$(jq -er '
    if (.status == "0x1" or .status == "0x01" or .status == "1" or .status == 1)
    then "success"
    else error("deployment transaction was not successful")
    end
  ' <<<"$receipt_json")" || fail "$ledger_key receipt does not prove success"
  receipt_contract_address="$(jq -er '
    .contractAddress
    | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))
  ' <<<"$receipt_json")" || fail "$ledger_key receipt contract address is invalid"
  validate_address "$ledger_key receipt contract" "$receipt_contract_address"
  assert_address_equal \
    "$ledger_key receipt contract" \
    "$deployed_address" \
    "$receipt_contract_address"
  receipt_block_raw="$(jq -er '
    .blockNumber
    | if type == "number" then tostring
      elif type == "string" then .
      else error("invalid deployment block")
      end
  ' <<<"$receipt_json")" || fail "$ledger_key receipt block number is invalid"
  if [[ "$receipt_block_raw" =~ ^0x[0-9a-fA-F]+$ ]]; then
    receipt_block="$(cast to-dec "$receipt_block_raw")" \
      || fail "$ledger_key receipt block could not be normalized"
  elif [[ "$receipt_block_raw" =~ ^[0-9]+$ ]]; then
    receipt_block="$receipt_block_raw"
  else
    fail "$ledger_key receipt block is malformed"
  fi
  [[ "$receipt_block" =~ ^[1-9][0-9]*$ ]] \
    || fail "$ledger_key receipt block must be greater than zero"
  receipt_block_hash="$(jq -er '
    .blockHash
    | select(type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    | ascii_downcase
  ' <<<"$receipt_json")" || fail "$ledger_key receipt block hash is invalid"
  validate_bytes32 "$ledger_key receipt block hash" "$receipt_block_hash"

  DEPLOYMENT_RECEIPTS="$(jq -cn \
    --argjson receipts "$DEPLOYMENT_RECEIPTS" \
    --arg key "$ledger_key" \
    --arg from "$DEPLOYMENT_OPERATOR" \
    --arg status "$receipt_status" \
    --arg contractAddress "$deployed_address" \
    --arg block "$receipt_block" \
    --arg blockHash "$receipt_block_hash" '
      $receipts + {
        ($key): {
          deploymentTxFrom: $from,
          deploymentReceiptStatus: $status,
          deploymentReceiptContractAddress: $contractAddress,
          deploymentBlock: ($block | tonumber),
          deploymentBlockHash: $blockHash
        }
      }
    ')" || fail "$ledger_key receipt evidence could not be canonicalized"
}

collect_broadcast_transaction() {
  local sequence="$1"
  local ledger_key="$2"
  local contract_name="$3"
  local transaction_type="$4"
  local function_signature="$5"
  local expected_input="$6"
  local contract_address="$7"
  local artifact_transaction
  local artifact_name
  local artifact_type
  local artifact_function
  local transaction_hash
  local artifact_from
  local artifact_to
  local artifact_input
  local artifact_nonce
  local tx_json
  local receipt_json
  local tx_hash
  local tx_from
  local tx_to
  local tx_input
  local tx_nonce
  local tx_block
  local tx_block_hash
  local receipt_hash
  local receipt_from
  local receipt_contract_address
  local receipt_block
  local receipt_block_hash
  local input_sha256

  validate_transaction_input "$contract_name expected transaction input" "$expected_input"
  artifact_transaction="$(
    jq -cer --argjson sequence "$sequence" '.transactions[$sequence]' "$RUN_PATH"
  )" || fail "$contract_name transaction $sequence is missing from the Foundry artifact"
  artifact_name="$(jq -er '.contractName' <<<"$artifact_transaction")"
  artifact_type="$(jq -er '.transactionType' <<<"$artifact_transaction")"
  artifact_function="$(jq -r '.function // ""' <<<"$artifact_transaction")"
  assert_equal "$contract_name artifact contract name" "$contract_name" "$artifact_name"
  assert_equal "$contract_name artifact transaction type" "$transaction_type" "$artifact_type"
  if [ "$transaction_type" = "CALL" ]; then
    assert_equal "$contract_name artifact function" "$function_signature" "$artifact_function"
  elif [ -n "$artifact_function" ]; then
    fail "$contract_name CREATE artifact unexpectedly names a function"
  fi
  transaction_hash="$(
    jq -er '.hash | select(type == "string" and test("^0x[0-9a-fA-F]{64}$")) | ascii_downcase' \
      <<<"$artifact_transaction"
  )" || fail "$contract_name artifact transaction hash is invalid"
  artifact_from="$(jq -er '.transaction.from | ascii_downcase' <<<"$artifact_transaction")"
  artifact_to="$(
    jq -r 'if .transaction.to == null then "null" else (.transaction.to | ascii_downcase) end' \
      <<<"$artifact_transaction"
  )"
  artifact_input="$(jq -er '.transaction.input | ascii_downcase' <<<"$artifact_transaction")"
  artifact_nonce="$(
    normalize_quantity "$contract_name artifact nonce" \
      "$(jq -r '.transaction.nonce' <<<"$artifact_transaction")"
  )"
  assert_address_equal "$contract_name artifact sender" "$DEPLOYMENT_OPERATOR" "$artifact_from"
  assert_equal "$contract_name transaction $sequence artifact input" "$expected_input" "$artifact_input"
  assert_equal "$contract_name transaction $sequence artifact nonce" "$EXPECTED_TRANSACTION_NONCE" "$artifact_nonce"
  if [ "$transaction_type" = "CREATE" ]; then
    assert_equal "$contract_name CREATE artifact target" null "$artifact_to"
  else
    assert_address_equal "$contract_name CALL artifact target" "$contract_address" "$artifact_to"
  fi

  tx_json="$(cast tx "$transaction_hash" --rpc-url "$RPC_URL" --json)" \
    || fail "$contract_name mined transaction could not be read"
  receipt_json="$(cast receipt "$transaction_hash" --rpc-url "$RPC_URL" --json)" \
    || fail "$contract_name mined receipt could not be read"
  [ "${#tx_json}" -le 1048576 ] && [ "${#receipt_json}" -le 1048576 ] \
    || fail "$contract_name mined evidence exceeds the 1 MiB per-record bound"
  tx_hash="$(jq -er '.hash | select(type == "string" and test("^0x[0-9a-fA-F]{64}$")) | ascii_downcase' <<<"$tx_json")"
  tx_from="$(jq -er '.from | select(type == "string" and test("^0x[0-9a-fA-F]{40}$")) | ascii_downcase' <<<"$tx_json")"
  tx_to="$(jq -r 'if .to == null then "null" else (.to | ascii_downcase) end' <<<"$tx_json")"
  tx_input="$(jq -er '(.input // .data) | select(type == "string") | ascii_downcase' <<<"$tx_json")"
  tx_nonce="$(normalize_quantity "$contract_name mined nonce" "$(jq -r '.nonce' <<<"$tx_json")")"
  tx_block="$(normalize_quantity "$contract_name mined block" "$(jq -r '.blockNumber' <<<"$tx_json")")"
  tx_block_hash="$(jq -er '.blockHash | select(type == "string" and test("^0x[0-9a-fA-F]{64}$")) | ascii_downcase' <<<"$tx_json")"
  receipt_hash="$(jq -er '.transactionHash | select(type == "string" and test("^0x[0-9a-fA-F]{64}$")) | ascii_downcase' <<<"$receipt_json")"
  receipt_from="$(jq -er '.from | select(type == "string" and test("^0x[0-9a-fA-F]{40}$")) | ascii_downcase' <<<"$receipt_json")"
  receipt_block="$(normalize_quantity "$contract_name receipt block" "$(jq -r '.blockNumber' <<<"$receipt_json")")"
  receipt_block_hash="$(jq -er '.blockHash | select(type == "string" and test("^0x[0-9a-fA-F]{64}$")) | ascii_downcase' <<<"$receipt_json")"
  if ! jq -e '(.status == "0x1") or (.status == "0x01") or (.status == "1") or (.status == 1)' \
    <<<"$receipt_json" >/dev/null; then
    fail "$contract_name transaction receipt does not prove success"
  fi
  assert_equal "$contract_name mined transaction hash" "$transaction_hash" "$tx_hash"
  assert_equal "$contract_name receipt transaction hash" "$transaction_hash" "$receipt_hash"
  assert_equal "$contract_name transaction/receipt block" "$tx_block" "$receipt_block"
  assert_equal "$contract_name transaction/receipt block hash" "$tx_block_hash" "$receipt_block_hash"
  assert_equal "$contract_name mined nonce" "$EXPECTED_TRANSACTION_NONCE" "$tx_nonce"
  assert_address_equal "$contract_name mined sender" "$DEPLOYMENT_OPERATOR" "$tx_from"
  assert_address_equal "$contract_name receipt sender" "$DEPLOYMENT_OPERATOR" "$receipt_from"
  validate_transaction_input "$contract_name mined transaction input" "$tx_input"
  assert_equal "$contract_name mined transaction input" "$expected_input" "$tx_input"
  assert_equal "$contract_name artifact/mined transaction input" "$artifact_input" "$tx_input"

  if [ "$transaction_type" = "CREATE" ]; then
    assert_equal "$contract_name mined CREATE target" null "$tx_to"
    receipt_contract_address="$(
      jq -er '
        .contractAddress
        | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))
        | ascii_downcase
      ' <<<"$receipt_json"
    )" || fail "$contract_name CREATE receipt contract address is invalid"
    assert_address_equal "$contract_name receipt contract" "$contract_address" "$receipt_contract_address"
  else
    assert_address_equal "$contract_name mined CALL target" "$contract_address" "$tx_to"
    jq -e '.contractAddress == null' <<<"$receipt_json" >/dev/null \
      || fail "$contract_name CALL receipt unexpectedly contains a created contract address"
    receipt_contract_address="null"
  fi
  input_sha256="$(transaction_input_sha256 "$tx_input")"
  validate_sha256 "$contract_name transaction input digest" "$input_sha256"

  BROADCAST_TRANSACTIONS="$(jq -cn \
    --argjson transactions "$BROADCAST_TRANSACTIONS" \
    --arg sequence "$sequence" \
    --arg contractKey "$ledger_key" \
    --arg contractName "$contract_name" \
    --arg transactionType "$transaction_type" \
    --arg functionSignature "$function_signature" \
    --arg transactionHash "$transaction_hash" \
    --arg transactionFrom "$(normalize_address "$DEPLOYMENT_OPERATOR")" \
    --arg transactionTo "$contract_address" \
    --arg transactionNonce "$tx_nonce" \
    --arg transactionInputSha256 "$input_sha256" \
    --arg receiptContractAddress "$contract_address" \
    --arg blockNumber "$receipt_block" \
    --arg blockHash "$receipt_block_hash" '
      $transactions + [{
        sequence: ($sequence | tonumber),
        contractKey: $contractKey,
        contractName: $contractName,
        transactionType: $transactionType,
        functionSignature: $functionSignature,
        transactionHash: $transactionHash,
        transactionFrom: $transactionFrom,
        transactionTo: (if $transactionType == "CREATE" then null else $transactionTo end),
        transactionNonce: ($transactionNonce | tonumber),
        transactionInputSha256: $transactionInputSha256,
        receiptStatus: "success",
        receiptContractAddress:
          (if $transactionType == "CREATE" then $receiptContractAddress else null end),
        blockNumber: ($blockNumber | tonumber),
        blockHash: $blockHash
      }]
    ')" || fail "$contract_name transaction ledger could not be canonicalized"
  if [ "$transaction_type" = "CREATE" ]; then
    DEPLOYMENT_RECEIPTS="$(jq -cn \
      --argjson receipts "$DEPLOYMENT_RECEIPTS" \
      --arg key "$ledger_key" \
      --arg from "$(normalize_address "$DEPLOYMENT_OPERATOR")" \
      --arg contractAddress "$contract_address" \
      --arg block "$receipt_block" \
      --arg blockHash "$receipt_block_hash" \
      --arg creationInputSha256 "$input_sha256" '
        $receipts + {
          ($key): {
            deploymentTxFrom: $from,
            deploymentReceiptStatus: "success",
            deploymentReceiptContractAddress: $contractAddress,
            deploymentBlock: ($block | tonumber),
            deploymentBlockHash: $blockHash,
            creationInputSha256: $creationInputSha256
          }
        }
      ')" || fail "$contract_name CREATE receipt ledger could not be canonicalized"
  fi
  EXPECTED_TRANSACTION_NONCE="$((EXPECTED_TRANSACTION_NONCE + 1))"
}

assert_runtime_code() {
  local contract_name="$1"
  local deployed_address="$2"
  local constructor_signature="$3"
  shift 3

  local creation_code
  local expected_runtime
  local deployed_runtime
  local expected_hash
  local deployed_hash

  creation_code="$(forge inspect "$contract_name" bytecode)" \
    || fail "$contract_name creation bytecode could not be inspected"
  [[ "$creation_code" =~ ^0x([0-9a-fA-F]{2})+$ ]] \
    || fail "$contract_name creation bytecode is malformed or empty"
  if [ -n "$constructor_signature" ]; then
    expected_runtime="$(
      cast call \
        --from "$DEPLOYMENT_OPERATOR" \
        --rpc-url "$RPC_URL" \
        --create "$creation_code" \
        "$constructor_signature" \
        "$@"
    )" || fail "$contract_name constructor re-execution failed"
  else
    expected_runtime="$(
      cast call \
        --from "$DEPLOYMENT_OPERATOR" \
        --rpc-url "$RPC_URL" \
        --create "$creation_code"
    )" || fail "$contract_name constructor re-execution failed"
  fi
  [[ "$expected_runtime" =~ ^0x([0-9a-fA-F]{2})+$ ]] \
    || fail "$contract_name constructor re-execution returned malformed or empty runtime bytecode"

  deployed_runtime="$(cast code "$deployed_address" --rpc-url "$RPC_URL")" \
    || fail "$contract_name deployed runtime bytecode could not be read"
  [[ "$deployed_runtime" =~ ^0x([0-9a-fA-F]{2})+$ ]] \
    || fail "$contract_name has malformed or empty runtime bytecode"
  expected_hash="$(cast keccak "$expected_runtime")"
  deployed_hash="$(cast keccak "$deployed_runtime")"
  assert_equal "$contract_name exact runtime hash" "$expected_hash" "$deployed_hash"
  printf '%s\n' "$deployed_hash"
}

for required in forge cast jq git node; do
  command -v "$required" >/dev/null 2>&1 || fail "$required is required"
done

# A chain-id check alone is not a network boundary. Accept only a literal IPv4
# loopback URL, then require the Anvil-specific node-info RPC before doing work.
if [[ ! "$RPC_URL" =~ ^http://127[.]0[.]0[.]1:[0-9]+$ ]]; then
  fail "ANVIL_RPC_URL must use literal 127.0.0.1 over HTTP with an explicit port"
fi

LIVE_CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL")"
assert_equal "local chain id" "$CHAIN_ID" "$LIVE_CHAIN_ID"

CLIENT_VERSION="$(cast rpc web3_clientVersion --rpc-url "$RPC_URL" | jq -r '.')"
case "$(printf '%s' "$CLIENT_VERSION" | tr '[:upper:]' '[:lower:]')" in
  *anvil*) ;;
  *) fail "loopback RPC does not identify itself as Anvil" ;;
esac
cast rpc anvil_nodeInfo --rpc-url "$RPC_URL" >/dev/null \
  || fail "loopback RPC does not expose Anvil node information"

ACCOUNTS_JSON="$(cast rpc eth_accounts --rpc-url "$RPC_URL")"
if [ "$(printf '%s' "$ACCOUNTS_JSON" | jq 'length')" -lt 10 ]; then
  fail "Anvil must expose at least ten unlocked accounts"
fi

DEPLOYMENT_OPERATOR="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[0]')"
DILIGENCE_RESULT_VERIFIER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[1]')"
SELLER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[2]')"
BUYER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[3]')"
TEE_IDENTITY="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[4]')"
CHALLENGE_CONTROLLER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[5]')"
DILIGENCE_GOVERNANCE_CONTROLLER="$CHALLENGE_CONTROLLER"
COMPUTE_VAULT_DEVELOPER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[6]')"
COMPUTE_VAULT_METERING_VERIFIER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[7]')"
EXECUTION_POLICY_ANCHOR_WRITER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[8]')"
DILIGENCE_ATTESTATION_VERIFIER="$(printf '%s' "$ACCOUNTS_JSON" | jq -r '.[9]')"

for account_entry in \
  "DEPLOYMENT_OPERATOR:$DEPLOYMENT_OPERATOR" \
  "DILIGENCE_RESULT_VERIFIER:$DILIGENCE_RESULT_VERIFIER" \
  "SELLER:$SELLER" \
  "BUYER:$BUYER" \
  "TEE_IDENTITY:$TEE_IDENTITY" \
  "CHALLENGE_CONTROLLER:$CHALLENGE_CONTROLLER" \
  "DILIGENCE_GOVERNANCE_CONTROLLER:$DILIGENCE_GOVERNANCE_CONTROLLER" \
  "COMPUTE_VAULT_DEVELOPER:$COMPUTE_VAULT_DEVELOPER" \
  "COMPUTE_VAULT_METERING_VERIFIER:$COMPUTE_VAULT_METERING_VERIFIER" \
  "EXECUTION_POLICY_ANCHOR_WRITER:$EXECUTION_POLICY_ANCHOR_WRITER" \
  "DILIGENCE_ATTESTATION_VERIFIER:$DILIGENCE_ATTESTATION_VERIFIER"; do
  validate_address "${account_entry%%:*}" "${account_entry#*:}"
done
if [ "$(normalize_address "$DEPLOYMENT_OPERATOR")" = "$(normalize_address "$DILIGENCE_RESULT_VERIFIER")" ]; then
  fail "operator and result verifier must be distinct Anvil accounts"
fi

if [ -n "${LOCAL_REHEARSAL_OUTPUT:-}" ]; then
  case "$LOCAL_REHEARSAL_OUTPUT" in
    /*) ;;
    *) fail "LOCAL_REHEARSAL_OUTPUT must be an absolute path" ;;
  esac
  mkdir -p "$LOCAL_REHEARSAL_OUTPUT"
  EVIDENCE_DIR="$(cd "$LOCAL_REHEARSAL_OUTPUT" && pwd -P)"
else
  EVIDENCE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dnai-fresh-suite-rehearsal.XXXXXX")"
fi
case "$EVIDENCE_DIR/" in
  "$ROOT_DIR/"*) fail "local rehearsal evidence must stay outside the repository" ;;
esac
mkdir -p "$EVIDENCE_DIR/receipts"

# Fixed, domain-separated synthetic commitments make the run repeatable without
# resembling a production identity, account, artifact, or CVM measurement.
TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT="$(cast keccak 'dnai/local-rehearsal/tinker-account/v1')"
TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH="$(cast keccak 'dnai/local-rehearsal/tinker-compose/v1')"
DILIGENCE_QVL_RELEASE_POLICY_HASH="$(cast keccak 'dnai/local-rehearsal/diligence-qvl-release-policy/v1')"
DEPLOYMENT_INTENT_SHA256_BYTES32="0x$(node -e '
  process.stdout.write(require("node:crypto").createHash("sha256")
    .update("dnai/local-rehearsal/deployment-intent/v1", "utf8").digest("hex"));
')"
REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32="0x$(node -e '
  process.stdout.write(require("node:crypto").createHash("sha256")
    .update("dnai/local-rehearsal/signed-reviewer-genesis-acceptance/v1", "utf8")
    .digest("hex"));
')"
DEPLOYMENT_INTENT_SHA256="sha256:${DEPLOYMENT_INTENT_SHA256_BYTES32#0x}"
REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256="sha256:${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32#0x}"
TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI=5000000000000000000
TINKER_ENCUMBRANCE_MAX_SPEND_WEI=2000000000000000000
EMAIL_ORACLE_UPGRADE_DELAY=172800
COMPUTE_VAULT_DEVELOPER_FEE_BPS=100

export DEPLOYMENT_OPERATOR
export DILIGENCE_GOVERNANCE_CONTROLLER
export DILIGENCE_RESULT_VERIFIER
export COMPUTE_VAULT_DEVELOPER
export COMPUTE_VAULT_METERING_VERIFIER
export COMPUTE_VAULT_DEVELOPER_FEE_BPS
export TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT
export TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH
export TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI
export TINKER_ENCUMBRANCE_MAX_SPEND_WEI
export EMAIL_ORACLE_UPGRADE_DELAY
export DEPLOYMENT_INTENT_SHA256_BYTES32
export REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32
export FOUNDRY_BROADCAST="$EVIDENCE_DIR/broadcast"
export FOUNDRY_CACHE_PATH="$EVIDENCE_DIR/cache"
export FOUNDRY_OUT="$EVIDENCE_DIR/out"

echo "== Local ephemeral fresh-suite rehearsal =="
echo "Client:              $CLIENT_VERSION"
echo "Chain ID shape:      $LIVE_CHAIN_ID"
echo "RPC:                 $RPC_URL (loopback Anvil only)"
echo "Signer mode:         unlocked Anvil JSON-RPC accounts"
echo "Operator:            $DEPLOYMENT_OPERATOR"
echo "Diligence controller: $DILIGENCE_GOVERNANCE_CONTROLLER"
echo "Result verifier:     $DILIGENCE_RESULT_VERIFIER"
echo "Compute developer:   $COMPUTE_VAULT_DEVELOPER"
echo "Metering verifier:   $COMPUTE_VAULT_METERING_VERIFIER"
echo "Policy anchor writer: $EXECUTION_POLICY_ANCHOR_WRITER"
echo "Evidence directory:  $EVIDENCE_DIR"

cd "$CONTRACTS_DIR"

echo
echo "== Compile and full contract test suite =="
forge build --sizes
forge test

echo
echo "== Non-broadcasting dry run =="
forge script script/DeployFreshSuite.s.sol:DeployFreshSuiteScript \
  --rpc-url "$RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

echo
echo "== Broadcast to local Anvil =="
forge script script/DeployFreshSuite.s.sol:DeployFreshSuiteScript \
  --rpc-url "$RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --unlocked \
  --broadcast \
  --slow

RUN_PATH="$FOUNDRY_BROADCAST/DeployFreshSuite.s.sol/$CHAIN_ID/run-latest.json"
[ -f "$RUN_PATH" ] || fail "broadcast artifact was not written to $RUN_PATH"

DILIGENCE_ADDRESS="$(contract_address DiligenceRoom)"
ENCUMBRANCE_ADDRESS="$(contract_address TinkerAccountEncumbrance)"
ROYALTY_ADDRESS="$(contract_address RoyaltyDistributor)"
CHALLENGE_ADDRESS="$(contract_address ChallengeRegistry)"
COMPUTE_VAULT_ADDRESS="$(contract_address ComputeCreditVault)"
EMAIL_ORACLE_ADDRESS="$(contract_address EmailOracleAuth)"
EXECUTION_POLICY_ANCHOR_ADDRESS="$(contract_address ExecutionPolicyAnchor)"
DILIGENCE_TX="$(contract_tx DiligenceRoom)"
ENCUMBRANCE_TX="$(contract_tx TinkerAccountEncumbrance)"
ROYALTY_TX="$(contract_tx RoyaltyDistributor)"
CHALLENGE_TX="$(contract_tx ChallengeRegistry)"
COMPUTE_VAULT_TX="$(contract_tx ComputeCreditVault)"
EMAIL_ORACLE_TX="$(contract_tx EmailOracleAuth)"
EXECUTION_POLICY_ANCHOR_TX="$(contract_tx ExecutionPolicyAnchor)"

for deployment_entry in \
  "DiligenceRoom:$DILIGENCE_ADDRESS:$DILIGENCE_TX" \
  "TinkerAccountEncumbrance:$ENCUMBRANCE_ADDRESS:$ENCUMBRANCE_TX" \
  "RoyaltyDistributor:$ROYALTY_ADDRESS:$ROYALTY_TX" \
  "ChallengeRegistry:$CHALLENGE_ADDRESS:$CHALLENGE_TX" \
  "ComputeCreditVault:$COMPUTE_VAULT_ADDRESS:$COMPUTE_VAULT_TX" \
  "EmailOracleAuth:$EMAIL_ORACLE_ADDRESS:$EMAIL_ORACLE_TX" \
  "ExecutionPolicyAnchor:$EXECUTION_POLICY_ANCHOR_ADDRESS:$EXECUTION_POLICY_ANCHOR_TX"; do
  contract_name="${deployment_entry%%:*}"
  remainder="${deployment_entry#*:}"
  contract_address_value="${remainder%%:*}"
  contract_tx_value="${remainder#*:}"
  validate_address "$contract_name deployment address" "$contract_address_value"
  validate_bytes32 "$contract_name deployment transaction" "$contract_tx_value"
done

collect_deployment_receipt diligenceRoom "$DILIGENCE_TX" "$DILIGENCE_ADDRESS"
collect_deployment_receipt tinkerAccountEncumbrance "$ENCUMBRANCE_TX" "$ENCUMBRANCE_ADDRESS"
collect_deployment_receipt royaltyDistributor "$ROYALTY_TX" "$ROYALTY_ADDRESS"
collect_deployment_receipt challengeRegistry "$CHALLENGE_TX" "$CHALLENGE_ADDRESS"
collect_deployment_receipt computeCreditVault "$COMPUTE_VAULT_TX" "$COMPUTE_VAULT_ADDRESS"
collect_deployment_receipt emailOracleAuth "$EMAIL_ORACLE_TX" "$EMAIL_ORACLE_ADDRESS"
collect_deployment_receipt executionPolicyAnchor "$EXECUTION_POLICY_ANCHOR_TX" "$EXECUTION_POLICY_ANCHOR_ADDRESS"
[ "$(jq -r 'length' <<<"$DEPLOYMENT_RECEIPTS")" = "7" ] \
  || fail "fresh deployment receipt bundle must contain seven contracts"

# Reconstruct every CREATE and setup CALL from the compiled source, then bind
# the Foundry artifact to the independently read transaction and receipt. The
# canonical core consumes only this normalized 13-record ledger.
DILIGENCE_CREATE_INPUT="$(
  creation_input \
    DiligenceRoom \
    'constructor(bool,address)' \
    true \
    "$DILIGENCE_GOVERNANCE_CONTROLLER"
)"
DILIGENCE_FREEZE_FEE_INPUT="$(cast calldata 'freezeFeeBps()' | tr '[:upper:]' '[:lower:]')"
DILIGENCE_ENABLE_SETTLEMENT_INPUT="$(cast calldata 'enableComputeSettlementPolicy()' | tr '[:upper:]' '[:lower:]')"
DILIGENCE_REQUIRE_COMPOSE_INPUT="$(cast calldata 'setComposeApprovalRequired(bool)' true | tr '[:upper:]' '[:lower:]')"
DILIGENCE_REQUIRE_IDENTITY_INPUT="$(cast calldata 'setTeeIdentityApprovalRequired(bool)' true | tr '[:upper:]' '[:lower:]')"
DILIGENCE_FREEZE_APPROVAL_INPUT="$(cast calldata 'freezeApprovalRequirements()' | tr '[:upper:]' '[:lower:]')"
ENCUMBRANCE_CREATE_INPUT="$(
  creation_input \
    TinkerAccountEncumbrance \
    'constructor(address,bytes32,bytes32,uint256,uint256)' \
    "$DEPLOYMENT_OPERATOR" \
    "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" \
    "$ZERO_BYTES32" \
    "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" \
    "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI"
)"
ROYALTY_CREATE_INPUT="$(
  creation_input RoyaltyDistributor 'constructor(address)' "$DEPLOYMENT_OPERATOR"
)"
CHALLENGE_CREATE_INPUT="$(creation_input ChallengeRegistry 'constructor(address)' "$DEPLOYMENT_OPERATOR")"
COMPUTE_VAULT_CREATE_INPUT="$(
  creation_input \
    ComputeCreditVault \
    'constructor(address,address,uint16)' \
    "$DEPLOYMENT_OPERATOR" \
    "$COMPUTE_VAULT_DEVELOPER" \
    "$COMPUTE_VAULT_DEVELOPER_FEE_BPS"
)"
COMPUTE_VAULT_FREEZE_FEE_INPUT="$(cast calldata 'freezeDeveloperFee()' | tr '[:upper:]' '[:lower:]')"
EMAIL_ORACLE_CREATE_INPUT="$(
  creation_input \
    EmailOracleAuth \
    'constructor(address,uint256,bool,bytes32,bytes32,bool)' \
    "$DEPLOYMENT_OPERATOR" \
    "$EMAIL_ORACLE_UPGRADE_DELAY" \
    false \
    "$ZERO_BYTES32" \
    "$ZERO_BYTES32" \
    true
)"
EXECUTION_POLICY_ANCHOR_CREATE_INPUT="$(
  creation_input \
    ExecutionPolicyAnchor \
    'constructor(address,bytes32,bytes32)' \
    "$DEPLOYMENT_OPERATOR" \
    "$DEPLOYMENT_INTENT_SHA256_BYTES32" \
    "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32"
)"
EXPECTED_TRANSACTION_NONCE="$(
  normalize_quantity \
    "first broadcast transaction nonce" \
    "$(jq -er '.transactions[0].transaction.nonce' "$RUN_PATH")"
)"

collect_broadcast_transaction 0 diligenceRoom DiligenceRoom CREATE 'constructor(bool,address)' "$DILIGENCE_CREATE_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 1 diligenceRoom DiligenceRoom CALL 'freezeFeeBps()' "$DILIGENCE_FREEZE_FEE_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 2 diligenceRoom DiligenceRoom CALL 'enableComputeSettlementPolicy()' "$DILIGENCE_ENABLE_SETTLEMENT_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 3 diligenceRoom DiligenceRoom CALL 'setComposeApprovalRequired(bool)' "$DILIGENCE_REQUIRE_COMPOSE_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 4 diligenceRoom DiligenceRoom CALL 'setTeeIdentityApprovalRequired(bool)' "$DILIGENCE_REQUIRE_IDENTITY_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 5 diligenceRoom DiligenceRoom CALL 'freezeApprovalRequirements()' "$DILIGENCE_FREEZE_APPROVAL_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 6 tinkerAccountEncumbrance TinkerAccountEncumbrance CREATE 'constructor(address,bytes32,bytes32,uint256,uint256)' "$ENCUMBRANCE_CREATE_INPUT" "$ENCUMBRANCE_ADDRESS"
collect_broadcast_transaction 7 royaltyDistributor RoyaltyDistributor CREATE 'constructor(address)' "$ROYALTY_CREATE_INPUT" "$ROYALTY_ADDRESS"
collect_broadcast_transaction 8 challengeRegistry ChallengeRegistry CREATE 'constructor(address)' "$CHALLENGE_CREATE_INPUT" "$CHALLENGE_ADDRESS"
collect_broadcast_transaction 9 computeCreditVault ComputeCreditVault CREATE 'constructor(address,address,uint16)' "$COMPUTE_VAULT_CREATE_INPUT" "$COMPUTE_VAULT_ADDRESS"
collect_broadcast_transaction 10 computeCreditVault ComputeCreditVault CALL 'freezeDeveloperFee()' "$COMPUTE_VAULT_FREEZE_FEE_INPUT" "$COMPUTE_VAULT_ADDRESS"
collect_broadcast_transaction 11 emailOracleAuth EmailOracleAuth CREATE 'constructor(address,uint256,bool,bytes32,bytes32,bool)' "$EMAIL_ORACLE_CREATE_INPUT" "$EMAIL_ORACLE_ADDRESS"
collect_broadcast_transaction 12 executionPolicyAnchor ExecutionPolicyAnchor CREATE 'constructor(address,bytes32,bytes32)' "$EXECUTION_POLICY_ANCHOR_CREATE_INPUT" "$EXECUTION_POLICY_ANCHOR_ADDRESS"

if [ "$(jq -r '.transactions | length' "$RUN_PATH")" != "13" ] \
  || [ "$(jq -r 'length' <<<"$BROADCAST_TRANSACTIONS")" != "13" ] \
  || [ "$(jq -r '[.[].transactionHash] | unique | length' <<<"$BROADCAST_TRANSACTIONS")" != "13" ]; then
  fail "fresh deployment evidence must contain exactly 13 distinct mined transactions"
fi
CONTRACT_ADDRESSES_JSON="$(jq -cn \
  --arg diligenceRoom "$DILIGENCE_ADDRESS" \
  --arg tinkerAccountEncumbrance "$ENCUMBRANCE_ADDRESS" \
  --arg royaltyDistributor "$ROYALTY_ADDRESS" \
  --arg challengeRegistry "$CHALLENGE_ADDRESS" \
  --arg computeCreditVault "$COMPUTE_VAULT_ADDRESS" \
  --arg emailOracleAuth "$EMAIL_ORACLE_ADDRESS" \
  --arg executionPolicyAnchor "$EXECUTION_POLICY_ANCHOR_ADDRESS" '
    {
      diligenceRoom: $diligenceRoom,
      tinkerAccountEncumbrance: $tinkerAccountEncumbrance,
      royaltyDistributor: $royaltyDistributor,
      challengeRegistry: $challengeRegistry,
      computeCreditVault: $computeCreditVault,
      emailOracleAuth: $emailOracleAuth,
      executionPolicyAnchor: $executionPolicyAnchor
    }
  ')"
BROADCAST_EVIDENCE="$(jq -cn \
  --argjson transactions "$BROADCAST_TRANSACTIONS" \
  --arg operatorAddress "$(normalize_address "$DEPLOYMENT_OPERATOR")" \
  --argjson contractAddresses "$CONTRACT_ADDRESSES_JSON" '
    {transactions:$transactions,operatorAddress:$operatorAddress,contractAddresses:$contractAddresses}
  ' | node --input-type=module -e '
    import fs from "node:fs";
    import { pathToFileURL } from "node:url";
    const core = await import(pathToFileURL(process.argv[1]));
    const value = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(JSON.stringify(core.freshBroadcastTransactionEvidenceFromLedger(
      value.transactions,
      { operatorAddress: value.operatorAddress, contractAddresses: value.contractAddresses },
    )));
  ' "$ROOT_DIR/scripts/cvm-launch-intent-core.mjs")" \
  || fail "canonical fresh broadcast transaction projection failed"
BROADCAST_TRANSACTIONS_SHA256="$(jq -er '.broadcast_transactions_sha256' <<<"$BROADCAST_EVIDENCE")"
validate_sha256 BROADCAST_TRANSACTIONS_SHA256 "$BROADCAST_TRANSACTIONS_SHA256"
[ "$(jq -r '.broadcast_transactions | length' <<<"$BROADCAST_EVIDENCE")" = "13" ] \
  || fail "canonical broadcast transaction projection must retain all 13 records"

echo
echo "== Exact runtime-bytecode proofs =="
DILIGENCE_RUNTIME_CODE_HASH="$(
  assert_runtime_code \
    DiligenceRoom \
    "$DILIGENCE_ADDRESS" \
    'constructor(bool,address)' \
    true \
    "$DILIGENCE_GOVERNANCE_CONTROLLER"
)"
ENCUMBRANCE_RUNTIME_CODE_HASH="$(
  assert_runtime_code \
    TinkerAccountEncumbrance \
    "$ENCUMBRANCE_ADDRESS" \
    'constructor(address,bytes32,bytes32,uint256,uint256)' \
    "$DEPLOYMENT_OPERATOR" \
    "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" \
    "$ZERO_BYTES32" \
    "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" \
    "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI"
)"
ROYALTY_RUNTIME_CODE_HASH="$(
  assert_runtime_code RoyaltyDistributor "$ROYALTY_ADDRESS" 'constructor(address)' "$DEPLOYMENT_OPERATOR"
)"
CHALLENGE_RUNTIME_CODE_HASH="$(
  assert_runtime_code ChallengeRegistry "$CHALLENGE_ADDRESS" 'constructor(address)' "$DEPLOYMENT_OPERATOR"
)"
COMPUTE_VAULT_RUNTIME_CODE_HASH="$(
  assert_runtime_code \
    ComputeCreditVault \
    "$COMPUTE_VAULT_ADDRESS" \
    'constructor(address,address,uint16)' \
    "$DEPLOYMENT_OPERATOR" \
    "$COMPUTE_VAULT_DEVELOPER" \
    "$COMPUTE_VAULT_DEVELOPER_FEE_BPS"
)"
EMAIL_ORACLE_RUNTIME_CODE_HASH="$(
  assert_runtime_code \
    EmailOracleAuth \
    "$EMAIL_ORACLE_ADDRESS" \
    'constructor(address,uint256,bool,bytes32,bytes32,bool)' \
    "$DEPLOYMENT_OPERATOR" \
    "$EMAIL_ORACLE_UPGRADE_DELAY" \
    false \
    "$ZERO_BYTES32" \
    "$ZERO_BYTES32" \
    true
)"
EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH="$(
  assert_runtime_code \
    ExecutionPolicyAnchor \
    "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
    'constructor(address,bytes32,bytes32)' \
    "$DEPLOYMENT_OPERATOR" \
    "$DEPLOYMENT_INTENT_SHA256_BYTES32" \
    "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32"
)"

echo
echo "== Initial roles and fail-closed policy =="
DILIGENCE_DEVELOPER="$(cast call "$DILIGENCE_ADDRESS" 'developer()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_DEVELOPER="$(cast call "$DILIGENCE_ADDRESS" 'initialDeveloper()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_RELEASE_GOVERNANCE_CONTROLLER="$(
  cast call "$DILIGENCE_ADDRESS" 'releaseGovernanceController()(address)' --rpc-url "$RPC_URL"
)"
DILIGENCE_PROTOCOL_FEE_RECIPIENT="$(
  cast call "$DILIGENCE_ADDRESS" 'protocolFeeRecipient()(address)' --rpc-url "$RPC_URL"
)"
DILIGENCE_PENDING_DEVELOPER="$(cast call "$DILIGENCE_ADDRESS" 'pendingDeveloper()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_PENDING_DEVELOPER_AT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingDeveloperActivatesAt()(uint256)')"
DILIGENCE_DEVELOPER_TRANSFER_DELAY="$(read_uint "$DILIGENCE_ADDRESS" 'DEVELOPER_TRANSFER_DELAY()(uint256)')"
DILIGENCE_PRODUCTION_RELEASE="$(cast call "$DILIGENCE_ADDRESS" 'productionRelease()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_DEAL_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'dealCount()(uint256)')"
DILIGENCE_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'resultVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_PENDING_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'pendingResultVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_PENDING_VERIFIER_AT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingResultVerifierActivatesAt()(uint256)')"
DILIGENCE_INITIAL_VERIFIER_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'resultVerifierFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_ATTESTATION_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'attestationVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_ATTESTATION_POLICY_HASH="$(cast call "$DILIGENCE_ADDRESS" 'attestationReleasePolicyHash()(bytes32)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_PENDING_ATTESTATION_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'pendingAttestationVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_PENDING_ATTESTATION_POLICY_HASH="$(cast call "$DILIGENCE_ADDRESS" 'pendingAttestationReleasePolicyHash()(bytes32)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_PENDING_ATTESTATION_AT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingAttestationBindingActivatesAt()(uint256)')"
DILIGENCE_INITIAL_ATTESTATION_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'attestationBindingFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_INITIAL_EVALUATOR_POLICIES_ABI="$(
  cast call "$DILIGENCE_ADDRESS" "$(cast calldata 'evaluatorPolicies()')" --rpc-url "$RPC_URL" \
    | tr '[:upper:]' '[:lower:]'
)"
DILIGENCE_INITIAL_APPROVED_EVALUATOR_POLICY_COUNT="$(
  read_uint "$DILIGENCE_ADDRESS" 'approvedEvaluatorPolicyCount()(uint256)'
)"
DILIGENCE_INITIAL_PENDING_EVALUATOR_POLICY_COUNT="$(
  read_uint "$DILIGENCE_ADDRESS" 'pendingEvaluatorPolicyCount()(uint256)'
)"
DILIGENCE_INITIAL_EVALUATOR_POLICY_SET_ROOT="$(
  cast call "$DILIGENCE_ADDRESS" 'evaluatorPolicySetRoot()(bytes32)' --rpc-url "$RPC_URL"
)"
DILIGENCE_INITIAL_EVALUATOR_POLICY_SET_FROZEN="$(
  cast call "$DILIGENCE_ADDRESS" 'evaluatorPolicySetFrozen()(bool)' --rpc-url "$RPC_URL"
)"
DILIGENCE_REQUIRED_EVALUATOR_POLICY_COUNT="$(
  read_uint "$DILIGENCE_ADDRESS" 'REQUIRED_EVALUATOR_POLICY_COUNT()(uint256)'
)"
DILIGENCE_COMPOSE_REQUIRED="$(cast call "$DILIGENCE_ADDRESS" 'composeApprovalRequired()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_IDENTITY_REQUIRED="$(cast call "$DILIGENCE_ADDRESS" 'teeIdentityApprovalRequired()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_APPROVAL_REQUIREMENTS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'approvalRequirementsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_APPROVED_COMPOSE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'approvedComposeCount()(uint256)')"
DILIGENCE_APPROVED_TEE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'approvedTeeIdentityCount()(uint256)')"
DILIGENCE_PENDING_COMPOSE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingComposeCount()(uint256)')"
DILIGENCE_PENDING_TEE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingTeeIdentityCount()(uint256)')"
DILIGENCE_COMPOSE_ADDITIONS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'composeAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_TEE_ADDITIONS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'teeIdentityAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_FEE_BPS="$(read_uint "$DILIGENCE_ADDRESS" 'feeBps()(uint256)')"
DILIGENCE_FEE_BPS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'feeBpsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_COMPUTE_SETTLEMENT_BPS="$(read_uint "$DILIGENCE_ADDRESS" 'COMPUTE_SETTLEMENT_BPS()(uint256)')"
DILIGENCE_COMPUTE_SETTLEMENT_POLICY_ENABLED="$(cast call "$DILIGENCE_ADDRESS" 'computeSettlementPolicyEnabled()(bool)' --rpc-url "$RPC_URL")"

ENCUMBRANCE_OWNER="$(cast call "$ENCUMBRANCE_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_OWNER="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingOwner()(address)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_ACCOUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'accountCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_MAX_ADD="$(read_uint "$ENCUMBRANCE_ADDRESS" 'maxAddBalanceWei()(uint256)')"
ENCUMBRANCE_MAX_SPEND="$(read_uint "$ENCUMBRANCE_ADDRESS" 'maxSpendWei()(uint256)')"
ENCUMBRANCE_COMPOSE_APPROVED="$(
  cast call \
    "$ENCUMBRANCE_ADDRESS" \
    'approvedComposeHashes(bytes32)(bool)' \
    "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH" \
    --rpc-url "$RPC_URL"
)"
ENCUMBRANCE_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'approvedComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_COMPOSE_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'approvedComposeCount()(uint256)')"
ENCUMBRANCE_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'managerRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_MANAGER_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'managerCount()(uint256)')"
ENCUMBRANCE_RELEASE_COMMITMENT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_RELEASE_MAX_ADD="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseMaxAddBalanceWei()(uint256)')"
ENCUMBRANCE_RELEASE_MAX_SPEND="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseMaxSpendWei()(uint256)')"
ENCUMBRANCE_RELEASE_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_RELEASE_COMPOSE_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseComposeCount()(uint256)')"
ENCUMBRANCE_RELEASE_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseManagerRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_RELEASE_MANAGER_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseManagerCount()(uint256)')"
ENCUMBRANCE_PENDING_ACCOUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingAccountCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_MAX_ADD="$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingMaxAddBalanceWei()(uint256)')"
ENCUMBRANCE_PENDING_MAX_SPEND="$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingMaxSpendWei()(uint256)')"
ENCUMBRANCE_PENDING_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingManagerRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_COMMITMENT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_AT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyActivatesAt()(uint64)')"
ENCUMBRANCE_PENDING_COMPOSE_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingComposeCount()(uint256)')"
ENCUMBRANCE_PENDING_MANAGER_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingManagerCount()(uint256)')"
ENCUMBRANCE_POLICY_FROZEN="$(cast call "$ENCUMBRANCE_ADDRESS" 'releasePolicyFrozen()(bool)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_EMERGENCY_HALTED="$(cast call "$ENCUMBRANCE_ADDRESS" 'emergencyHalted()(bool)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_EXPECTED_EMPTY_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'computeComposeRoot(bytes32[])(bytes32)' '[]' --rpc-url "$RPC_URL")"
ENCUMBRANCE_EXPECTED_EMPTY_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'computeManagerRoot(address[])(bytes32)' '[]' --rpc-url "$RPC_URL")"

ROYALTY_OWNER="$(cast call "$ROYALTY_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
ROYALTY_PENDING_OWNER="$(cast call "$ROYALTY_ADDRESS" 'pendingOwner()(address)' --rpc-url "$RPC_URL")"
ROYALTY_PAUSED="$(cast call "$ROYALTY_ADDRESS" 'paused()(bool)' --rpc-url "$RPC_URL")"
ROYALTY_SETTLEMENT_VERIFIER="$(cast call "$ROYALTY_ADDRESS" 'settlementVerifier()(address)' --rpc-url "$RPC_URL")"
ROYALTY_QVL_VERIFIER="$(cast call "$ROYALTY_ADDRESS" 'qvlVerifier()(address)' --rpc-url "$RPC_URL")"
ROYALTY_EXECUTION_POLICY_ANCHOR="$(cast call "$ROYALTY_ADDRESS" 'executionPolicyAnchor()(address)' --rpc-url "$RPC_URL")"
ROYALTY_ANCHOR_WRITER_RELEASE="$(cast call "$ROYALTY_ADDRESS" 'anchorWriterReleaseCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ROYALTY_RELEASE_POLICY="$(cast call "$ROYALTY_ADDRESS" 'releasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ROYALTY_AUTHORITY_NONCE="$(read_uint "$ROYALTY_ADDRESS" 'authorityNonce()(uint256)')"
ROYALTY_PENDING_AUTHORITY_AT="$(read_uint "$ROYALTY_ADDRESS" 'pendingAuthorityActivatesAt()(uint64)')"
ROYALTY_INITIAL_PENDING="$(
  read_uint "$ROYALTY_ADDRESS" 'pending(address,address)(uint256)' "$ZERO_ADDRESS" "$DEPLOYMENT_OPERATOR"
)"
CHALLENGE_OWNER="$(cast call "$CHALLENGE_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
CHALLENGE_PENDING_OWNER="$(cast call "$CHALLENGE_ADDRESS" 'pendingOwner()(address)' --rpc-url "$RPC_URL")"
CHALLENGE_PAUSED="$(cast call "$CHALLENGE_ADDRESS" 'registryPaused()(bool)' --rpc-url "$RPC_URL")"
CHALLENGE_INITIAL_COUNT="$(read_uint "$CHALLENGE_ADDRESS" 'challengeCount()(uint256)')"
CHALLENGE_NEXT_ID="$(read_uint "$CHALLENGE_ADDRESS" 'nextChallengeId()(uint256)')"
CHALLENGE_MIN_VERSION_REVIEW_DELAY="$(read_uint "$CHALLENGE_ADDRESS" 'MIN_VERSION_REVIEW_DELAY()(uint64)')"

COMPUTE_VAULT_OWNER="$(cast call "$COMPUTE_VAULT_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_DEVELOPER_READ="$(cast call "$COMPUTE_VAULT_ADDRESS" 'developer()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_METERING_VERIFIER_READ="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_METERING_QVL_VERIFIER_READ="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringQvlVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_METERING_POLICY_SET_HASH="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringPolicySetHash()(bytes32)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_VERIFIER="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_QVL_VERIFIER="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringQvlVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_POLICY_SET_HASH="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringPolicySetHash()(bytes32)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_AT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringBindingActivatesAt()(uint64)')"
COMPUTE_VAULT_METERING_BINDING_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringBindingFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PAUSED="$(cast call "$COMPUTE_VAULT_ADDRESS" 'paused()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_FEE_BPS="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'developerFeeBps()(uint16)')"
COMPUTE_VAULT_FEE_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'developerFeeFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_ALLOWED_ASSET_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'allowedAssetCount()(uint256)')"
COMPUTE_VAULT_ACTIVE_RATE_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'activeRatePolicyCount()(uint256)')"
COMPUTE_VAULT_APPROVED_COMPOSE_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'approvedComposeCount()(uint256)')"
COMPUTE_VAULT_APPROVED_TEE_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'approvedTeeIdentityCount()(uint256)')"
COMPUTE_VAULT_PENDING_ASSET_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'pendingAssetCount()(uint256)')"
COMPUTE_VAULT_PENDING_RATE_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'pendingRatePolicyCount()(uint256)')"
COMPUTE_VAULT_PENDING_COMPOSE_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'pendingComposeCount()(uint256)')"
COMPUTE_VAULT_PENDING_TEE_COUNT="$(read_uint "$COMPUTE_VAULT_ADDRESS" 'pendingTeeIdentityCount()(uint256)')"
COMPUTE_VAULT_COMPOSE_POLICY_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'composePolicyFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_TEE_ADDITIONS_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'teeIdentityAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_RATE_ADDITIONS_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'ratePolicyAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_ASSET_ADDITIONS_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'assetAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"

EMAIL_ORACLE_OWNER="$(cast call "$EMAIL_ORACLE_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_PENDING_OWNER="$(cast call "$EMAIL_ORACLE_ADDRESS" 'pendingOwner()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_PRODUCTION_RELEASE="$(cast call "$EMAIL_ORACLE_ADDRESS" 'productionRelease()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_DELAY="$(read_uint "$EMAIL_ORACLE_ADDRESS" 'ORACLE_UPGRADE_DELAY()(uint256)')"
EMAIL_ORACLE_ALLOW_ANY="$(cast call "$EMAIL_ORACLE_ADDRESS" 'allowAnyDevice()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_CODE_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'oracleCodeFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_CONSUMERS_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'consumerRegistryFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_MANAGER_ADDITIONS_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'consumerManagerAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsBindingFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_ALLOWED_COMPOSE_COUNT="$(read_uint "$EMAIL_ORACLE_ADDRESS" 'allowedOracleComposeHashCount()(uint256)')"
EMAIL_ORACLE_PENDING_COMPOSE_COUNT="$(read_uint "$EMAIL_ORACLE_ADDRESS" 'pendingOracleComposeHashCount()(uint256)')"
EMAIL_ORACLE_ALLOWED_DEVICE_COUNT="$(read_uint "$EMAIL_ORACLE_ADDRESS" 'allowedDeviceIdCount()(uint256)')"
EMAIL_ORACLE_MANAGER_COUNT="$(read_uint "$EMAIL_ORACLE_ADDRESS" 'consumerManagerCount()(uint256)')"
EMAIL_ORACLE_CONSUMER_COMPOSE_COUNT="$(read_uint "$EMAIL_ORACLE_ADDRESS" 'totalConsumerComposeHashCount()(uint256)')"
EMAIL_ORACLE_RELEASE_COMPOSE="$(cast call "$EMAIL_ORACLE_ADDRESS" 'releaseOracleComposeHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RELEASE_DEVICE="$(cast call "$EMAIL_ORACLE_ADDRESS" 'releaseDeviceId()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RELEASE_MANAGER="$(cast call "$EMAIL_ORACLE_ADDRESS" 'releaseConsumerManager()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RELEASE_APP="$(cast call "$EMAIL_ORACLE_ADDRESS" 'releaseConsumerAppId()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RELEASE_CONSUMER_COMPOSE="$(cast call "$EMAIL_ORACLE_ADDRESS" 'releaseConsumerComposeHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_CONTRACT="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsContract()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_RUNTIME_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsRuntimeCodeHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_IMPLEMENTATION="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsImplementation()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsImplementationRuntimeCodeHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_REGISTRATION_TX="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsRegistrationTxHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_REGISTRATION_BLOCK="$(read_uint "$EMAIL_ORACLE_ADDRESS" 'kmsRegistrationBlock()(uint64)')"
EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsRegistrationBlockHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_BOOT_INFO_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'targetBootInfoHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RESTART_PROOF_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'restartKeyDerivationProofHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RELEASE_READY="$(cast call "$EMAIL_ORACLE_ADDRESS" 'releaseConfigurationReady()(bool)' --rpc-url "$RPC_URL")"

EXECUTION_POLICY_ANCHOR_OWNER="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_DEPLOYMENT_INTENT_SHA256_BYTES32="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'deploymentIntentSha256()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_REVIEWER_GENESIS_ACCEPTANCE_SHA256_BYTES32="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'reviewerAuthorityGenesisAcceptanceSha256()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_INITIAL_WRITER="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writer()(address)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_INITIAL_RELEASE="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerReleaseCommitment()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_WRITER="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriter()(address)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_RELEASE="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriterReleaseCommitment()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_AT="$(read_uint "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriterActivatesAt()(uint64)')"
EXECUTION_POLICY_ANCHOR_INITIAL_ROTATIONS_FROZEN="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerRotationsFrozen()(bool)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_INITIAL_PAUSED="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'paused()(bool)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_INITIAL_SEQUENCE="$(read_uint "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalSequence()(uint256)')"
EXECUTION_POLICY_ANCHOR_INITIAL_HEAD="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalHead()(bytes32)' --rpc-url "$RPC_URL")"

assert_address_equal "DiligenceRoom developer" "$DEPLOYMENT_OPERATOR" "$DILIGENCE_DEVELOPER"
assert_address_equal "DiligenceRoom initial developer" "$DEPLOYMENT_OPERATOR" "$DILIGENCE_INITIAL_DEVELOPER"
assert_address_equal \
  "DiligenceRoom immutable release governance controller" \
  "$DILIGENCE_GOVERNANCE_CONTROLLER" \
  "$DILIGENCE_RELEASE_GOVERNANCE_CONTROLLER"
assert_address_equal \
  "DiligenceRoom immutable protocol fee recipient" \
  "$DILIGENCE_GOVERNANCE_CONTROLLER" \
  "$DILIGENCE_PROTOCOL_FEE_RECIPIENT"
assert_address_equal "DiligenceRoom initial pending developer" "$ZERO_ADDRESS" "$DILIGENCE_PENDING_DEVELOPER"
assert_equal "DiligenceRoom initial pending developer time" 0 "$DILIGENCE_PENDING_DEVELOPER_AT"
assert_equal "DiligenceRoom developer transfer delay" 172800 "$DILIGENCE_DEVELOPER_TRANSFER_DELAY"
assert_equal "DiligenceRoom production posture" true "$DILIGENCE_PRODUCTION_RELEASE"
assert_equal "DiligenceRoom initial deal count" 0 "$DILIGENCE_DEAL_COUNT"
assert_address_equal "DiligenceRoom initial result verifier" "$ZERO_ADDRESS" "$DILIGENCE_VERIFIER"
assert_address_equal "DiligenceRoom initial pending result verifier" "$ZERO_ADDRESS" "$DILIGENCE_INITIAL_PENDING_VERIFIER"
assert_equal "DiligenceRoom initial pending result-verifier time" 0 "$DILIGENCE_INITIAL_PENDING_VERIFIER_AT"
assert_equal "DiligenceRoom initial result-verifier binding open" false "$DILIGENCE_INITIAL_VERIFIER_FROZEN"
assert_address_equal "DiligenceRoom initial attestation verifier" "$ZERO_ADDRESS" "$DILIGENCE_INITIAL_ATTESTATION_VERIFIER"
assert_equal "DiligenceRoom initial attestation policy" "$ZERO_BYTES32" "$DILIGENCE_INITIAL_ATTESTATION_POLICY_HASH"
assert_address_equal "DiligenceRoom initial pending attestation verifier" "$ZERO_ADDRESS" "$DILIGENCE_INITIAL_PENDING_ATTESTATION_VERIFIER"
assert_equal "DiligenceRoom initial pending attestation policy" "$ZERO_BYTES32" "$DILIGENCE_INITIAL_PENDING_ATTESTATION_POLICY_HASH"
assert_equal "DiligenceRoom initial pending attestation time" 0 "$DILIGENCE_INITIAL_PENDING_ATTESTATION_AT"
assert_equal "DiligenceRoom initial attestation binding open" false "$DILIGENCE_INITIAL_ATTESTATION_FROZEN"
assert_equal "DiligenceRoom initial evaluator policies" "$ZERO_EVALUATOR_POLICIES_ABI" "$DILIGENCE_INITIAL_EVALUATOR_POLICIES_ABI"
assert_equal "DiligenceRoom initial approved evaluator policy count" 0 "$DILIGENCE_INITIAL_APPROVED_EVALUATOR_POLICY_COUNT"
assert_equal "DiligenceRoom initial pending evaluator policy count" 0 "$DILIGENCE_INITIAL_PENDING_EVALUATOR_POLICY_COUNT"
assert_equal "DiligenceRoom initial evaluator policy-set root" "$ZERO_BYTES32" "$DILIGENCE_INITIAL_EVALUATOR_POLICY_SET_ROOT"
assert_equal "DiligenceRoom initial evaluator policy-set open" false "$DILIGENCE_INITIAL_EVALUATOR_POLICY_SET_FROZEN"
assert_equal "DiligenceRoom required evaluator policy count" 3 "$DILIGENCE_REQUIRED_EVALUATOR_POLICY_COUNT"
assert_equal "DiligenceRoom compose gate" true "$DILIGENCE_COMPOSE_REQUIRED"
assert_equal "DiligenceRoom identity gate" true "$DILIGENCE_IDENTITY_REQUIRED"
assert_equal "DiligenceRoom frozen gate requirements" true "$DILIGENCE_APPROVAL_REQUIREMENTS_FROZEN"
assert_equal "DiligenceRoom initial approved compose count" 0 "$DILIGENCE_APPROVED_COMPOSE_COUNT"
assert_equal "DiligenceRoom initial approved TEE count" 0 "$DILIGENCE_APPROVED_TEE_COUNT"
assert_equal "DiligenceRoom initial pending compose count" 0 "$DILIGENCE_PENDING_COMPOSE_COUNT"
assert_equal "DiligenceRoom initial pending TEE count" 0 "$DILIGENCE_PENDING_TEE_COUNT"
assert_equal "DiligenceRoom initial compose additions open" false "$DILIGENCE_COMPOSE_ADDITIONS_FROZEN"
assert_equal "DiligenceRoom initial TEE additions open" false "$DILIGENCE_TEE_ADDITIONS_FROZEN"
assert_equal "DiligenceRoom fee" 100 "$DILIGENCE_FEE_BPS"
assert_equal "DiligenceRoom fee freeze" true "$DILIGENCE_FEE_BPS_FROZEN"
assert_equal "DiligenceRoom compute settlement tariff" 100 "$DILIGENCE_COMPUTE_SETTLEMENT_BPS"
assert_equal "DiligenceRoom compute settlement policy" true "$DILIGENCE_COMPUTE_SETTLEMENT_POLICY_ENABLED"
assert_address_equal "TinkerAccountEncumbrance owner" "$DEPLOYMENT_OPERATOR" "$ENCUMBRANCE_OWNER"
assert_equal "Tinker account commitment" "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" "$ENCUMBRANCE_ACCOUNT"
assert_equal "Tinker add-balance cap" "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" "$ENCUMBRANCE_MAX_ADD"
assert_equal "Tinker spend cap" "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI" "$ENCUMBRANCE_MAX_SPEND"
assert_address_equal "Tinker pending owner" "$ZERO_ADDRESS" "$ENCUMBRANCE_PENDING_OWNER"
assert_equal "Tinker initial release compose approval" false "$ENCUMBRANCE_COMPOSE_APPROVED"
assert_equal "Tinker initial empty compose root" "$ENCUMBRANCE_EXPECTED_EMPTY_COMPOSE_ROOT" "$ENCUMBRANCE_COMPOSE_ROOT"
assert_equal "Tinker initial compose count" 0 "$ENCUMBRANCE_COMPOSE_COUNT"
assert_equal "Tinker initial manager root" "$ENCUMBRANCE_EXPECTED_EMPTY_MANAGER_ROOT" "$ENCUMBRANCE_MANAGER_ROOT"
assert_equal "Tinker initial manager count" 0 "$ENCUMBRANCE_MANAGER_COUNT"
assert_equal "Tinker empty release commitment" "$ZERO_BYTES32" "$ENCUMBRANCE_RELEASE_COMMITMENT"
assert_equal "Tinker empty release add-balance cap" 0 "$ENCUMBRANCE_RELEASE_MAX_ADD"
assert_equal "Tinker empty release spend cap" 0 "$ENCUMBRANCE_RELEASE_MAX_SPEND"
assert_equal "Tinker empty release compose root" "$ZERO_BYTES32" "$ENCUMBRANCE_RELEASE_COMPOSE_ROOT"
assert_equal "Tinker empty release compose count" 0 "$ENCUMBRANCE_RELEASE_COMPOSE_COUNT"
assert_equal "Tinker empty release manager root" "$ZERO_BYTES32" "$ENCUMBRANCE_RELEASE_MANAGER_ROOT"
assert_equal "Tinker empty release manager count" 0 "$ENCUMBRANCE_RELEASE_MANAGER_COUNT"
assert_equal "Tinker empty pending account" "$ZERO_BYTES32" "$ENCUMBRANCE_PENDING_ACCOUNT"
assert_equal "Tinker empty pending add-balance cap" 0 "$ENCUMBRANCE_PENDING_MAX_ADD"
assert_equal "Tinker empty pending spend cap" 0 "$ENCUMBRANCE_PENDING_MAX_SPEND"
assert_equal "Tinker empty pending compose root" "$ZERO_BYTES32" "$ENCUMBRANCE_PENDING_COMPOSE_ROOT"
assert_equal "Tinker empty pending manager root" "$ZERO_BYTES32" "$ENCUMBRANCE_PENDING_MANAGER_ROOT"
assert_equal "Tinker empty pending commitment" "$ZERO_BYTES32" "$ENCUMBRANCE_PENDING_COMMITMENT"
assert_equal "Tinker empty pending activation" 0 "$ENCUMBRANCE_PENDING_AT"
assert_equal "Tinker empty pending compose count" 0 "$ENCUMBRANCE_PENDING_COMPOSE_COUNT"
assert_equal "Tinker empty pending manager count" 0 "$ENCUMBRANCE_PENDING_MANAGER_COUNT"
assert_equal "Tinker release policy initially open" false "$ENCUMBRANCE_POLICY_FROZEN"
assert_equal "Tinker fresh deployment halted" true "$ENCUMBRANCE_EMERGENCY_HALTED"
assert_address_equal "RoyaltyDistributor owner" "$DEPLOYMENT_OPERATOR" "$ROYALTY_OWNER"
assert_address_equal "RoyaltyDistributor pending owner" "$ZERO_ADDRESS" "$ROYALTY_PENDING_OWNER"
assert_equal "RoyaltyDistributor fresh deployment paused" true "$ROYALTY_PAUSED"
assert_address_equal "RoyaltyDistributor empty settlement verifier" "$ZERO_ADDRESS" "$ROYALTY_SETTLEMENT_VERIFIER"
assert_address_equal "RoyaltyDistributor empty QVL verifier" "$ZERO_ADDRESS" "$ROYALTY_QVL_VERIFIER"
assert_address_equal "RoyaltyDistributor empty policy anchor" "$ZERO_ADDRESS" "$ROYALTY_EXECUTION_POLICY_ANCHOR"
assert_equal "RoyaltyDistributor empty anchor-writer release" "$ZERO_BYTES32" "$ROYALTY_ANCHOR_WRITER_RELEASE"
assert_equal "RoyaltyDistributor empty release policy" "$ZERO_BYTES32" "$ROYALTY_RELEASE_POLICY"
assert_equal "RoyaltyDistributor initial authority nonce" 0 "$ROYALTY_AUTHORITY_NONCE"
assert_equal "RoyaltyDistributor empty pending authority" 0 "$ROYALTY_PENDING_AUTHORITY_AT"
assert_equal "RoyaltyDistributor initial pending balance" 0 "$ROYALTY_INITIAL_PENDING"
assert_address_equal "ChallengeRegistry owner" "$DEPLOYMENT_OPERATOR" "$CHALLENGE_OWNER"
assert_address_equal "ChallengeRegistry pending owner" "$ZERO_ADDRESS" "$CHALLENGE_PENDING_OWNER"
assert_equal "ChallengeRegistry initial pause" false "$CHALLENGE_PAUSED"
assert_equal "ChallengeRegistry initial count" 0 "$CHALLENGE_INITIAL_COUNT"
assert_equal "ChallengeRegistry initial next id" 1 "$CHALLENGE_NEXT_ID"
assert_equal "ChallengeRegistry review delay" 172800 "$CHALLENGE_MIN_VERSION_REVIEW_DELAY"
assert_address_equal "ComputeCreditVault owner" "$DEPLOYMENT_OPERATOR" "$COMPUTE_VAULT_OWNER"
assert_address_equal "ComputeCreditVault developer" "$COMPUTE_VAULT_DEVELOPER" "$COMPUTE_VAULT_DEVELOPER_READ"
assert_address_equal "ComputeCreditVault empty metering verifier" "$ZERO_ADDRESS" "$COMPUTE_VAULT_METERING_VERIFIER_READ"
assert_address_equal "ComputeCreditVault empty metering QVL verifier" "$ZERO_ADDRESS" "$COMPUTE_VAULT_METERING_QVL_VERIFIER_READ"
assert_equal "ComputeCreditVault empty metering policy" "$ZERO_BYTES32" "$COMPUTE_VAULT_METERING_POLICY_SET_HASH"
assert_address_equal "ComputeCreditVault empty pending meter" "$ZERO_ADDRESS" "$COMPUTE_VAULT_PENDING_METERING_VERIFIER"
assert_address_equal "ComputeCreditVault empty pending metering QVL" "$ZERO_ADDRESS" "$COMPUTE_VAULT_PENDING_METERING_QVL_VERIFIER"
assert_equal "ComputeCreditVault empty pending metering policy" "$ZERO_BYTES32" "$COMPUTE_VAULT_PENDING_METERING_POLICY_SET_HASH"
assert_equal "ComputeCreditVault empty pending metering time" 0 "$COMPUTE_VAULT_PENDING_METERING_AT"
assert_equal "ComputeCreditVault metering binding initially open" false "$COMPUTE_VAULT_METERING_BINDING_FROZEN"
assert_equal "ComputeCreditVault initially paused" true "$COMPUTE_VAULT_PAUSED"
assert_equal "ComputeCreditVault developer fee" "$COMPUTE_VAULT_DEVELOPER_FEE_BPS" "$COMPUTE_VAULT_FEE_BPS"
assert_equal "ComputeCreditVault developer fee freeze" true "$COMPUTE_VAULT_FEE_FROZEN"
assert_equal "ComputeCreditVault empty asset admission" 0 "$COMPUTE_VAULT_ALLOWED_ASSET_COUNT"
assert_equal "ComputeCreditVault empty rate admission" 0 "$COMPUTE_VAULT_ACTIVE_RATE_COUNT"
assert_equal "ComputeCreditVault empty compose admission" 0 "$COMPUTE_VAULT_APPROVED_COMPOSE_COUNT"
assert_equal "ComputeCreditVault empty TEE admission" 0 "$COMPUTE_VAULT_APPROVED_TEE_COUNT"
assert_equal "ComputeCreditVault empty pending asset admission" 0 "$COMPUTE_VAULT_PENDING_ASSET_COUNT"
assert_equal "ComputeCreditVault empty pending rate admission" 0 "$COMPUTE_VAULT_PENDING_RATE_COUNT"
assert_equal "ComputeCreditVault empty pending compose admission" 0 "$COMPUTE_VAULT_PENDING_COMPOSE_COUNT"
assert_equal "ComputeCreditVault empty pending TEE admission" 0 "$COMPUTE_VAULT_PENDING_TEE_COUNT"
assert_equal "ComputeCreditVault mutable compose onboarding" false "$COMPUTE_VAULT_COMPOSE_POLICY_FROZEN"
assert_equal "ComputeCreditVault mutable TEE onboarding" false "$COMPUTE_VAULT_TEE_ADDITIONS_FROZEN"
assert_equal "ComputeCreditVault mutable rate onboarding" false "$COMPUTE_VAULT_RATE_ADDITIONS_FROZEN"
assert_equal "ComputeCreditVault mutable asset onboarding" false "$COMPUTE_VAULT_ASSET_ADDITIONS_FROZEN"
assert_address_equal "EmailOracleAuth owner" "$DEPLOYMENT_OPERATOR" "$EMAIL_ORACLE_OWNER"
assert_address_equal "EmailOracleAuth pending owner" "$ZERO_ADDRESS" "$EMAIL_ORACLE_PENDING_OWNER"
assert_equal "EmailOracleAuth production posture" true "$EMAIL_ORACLE_PRODUCTION_RELEASE"
assert_equal "EmailOracleAuth upgrade delay" "$EMAIL_ORACLE_UPGRADE_DELAY" "$EMAIL_ORACLE_DELAY"
assert_equal "EmailOracleAuth deny-all device policy" false "$EMAIL_ORACLE_ALLOW_ANY"
assert_equal "EmailOracleAuth mutable code policy" false "$EMAIL_ORACLE_CODE_FROZEN"
assert_equal "EmailOracleAuth mutable consumer policy" false "$EMAIL_ORACLE_CONSUMERS_FROZEN"
assert_equal "EmailOracleAuth mutable manager admissions" false "$EMAIL_ORACLE_MANAGER_ADDITIONS_FROZEN"
assert_equal "EmailOracleAuth mutable KMS binding" false "$EMAIL_ORACLE_KMS_FROZEN"
assert_equal "EmailOracleAuth empty compose admissions" 0 "$EMAIL_ORACLE_ALLOWED_COMPOSE_COUNT"
assert_equal "EmailOracleAuth empty pending compose admissions" 0 "$EMAIL_ORACLE_PENDING_COMPOSE_COUNT"
assert_equal "EmailOracleAuth empty device admissions" 0 "$EMAIL_ORACLE_ALLOWED_DEVICE_COUNT"
assert_equal "EmailOracleAuth empty manager admissions" 0 "$EMAIL_ORACLE_MANAGER_COUNT"
assert_equal "EmailOracleAuth empty consumer compose admissions" 0 "$EMAIL_ORACLE_CONSUMER_COMPOSE_COUNT"
assert_equal "EmailOracleAuth empty release compose" "$ZERO_BYTES32" "$EMAIL_ORACLE_RELEASE_COMPOSE"
assert_equal "EmailOracleAuth empty release device" "$ZERO_BYTES32" "$EMAIL_ORACLE_RELEASE_DEVICE"
assert_address_equal "EmailOracleAuth empty release manager" "$ZERO_ADDRESS" "$EMAIL_ORACLE_RELEASE_MANAGER"
assert_address_equal "EmailOracleAuth empty release app" "$ZERO_ADDRESS" "$EMAIL_ORACLE_RELEASE_APP"
assert_equal "EmailOracleAuth empty release consumer compose" "$ZERO_BYTES32" "$EMAIL_ORACLE_RELEASE_CONSUMER_COMPOSE"
assert_address_equal "EmailOracleAuth empty KMS contract" "$ZERO_ADDRESS" "$EMAIL_ORACLE_KMS_CONTRACT"
assert_equal "EmailOracleAuth empty KMS runtime hash" "$ZERO_BYTES32" "$EMAIL_ORACLE_KMS_RUNTIME_HASH"
assert_address_equal "EmailOracleAuth empty KMS implementation" "$ZERO_ADDRESS" "$EMAIL_ORACLE_KMS_IMPLEMENTATION"
assert_equal "EmailOracleAuth empty KMS implementation runtime hash" "$ZERO_BYTES32" "$EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_HASH"
assert_equal "EmailOracleAuth empty KMS registration tx" "$ZERO_BYTES32" "$EMAIL_ORACLE_KMS_REGISTRATION_TX"
assert_equal "EmailOracleAuth empty KMS registration block" 0 "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK"
assert_equal "EmailOracleAuth empty KMS registration block hash" "$ZERO_BYTES32" "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH"
assert_equal "EmailOracleAuth empty target boot info" "$ZERO_BYTES32" "$EMAIL_ORACLE_BOOT_INFO_HASH"
assert_equal "EmailOracleAuth empty restart proof" "$ZERO_BYTES32" "$EMAIL_ORACLE_RESTART_PROOF_HASH"
assert_equal "EmailOracleAuth release not ready" false "$EMAIL_ORACLE_RELEASE_READY"
assert_address_equal "ExecutionPolicyAnchor owner" "$DEPLOYMENT_OPERATOR" "$EXECUTION_POLICY_ANCHOR_OWNER"
assert_equal \
  "ExecutionPolicyAnchor deployment intent commitment" \
  "$DEPLOYMENT_INTENT_SHA256_BYTES32" \
  "$EXECUTION_POLICY_ANCHOR_DEPLOYMENT_INTENT_SHA256_BYTES32"
assert_equal \
  "ExecutionPolicyAnchor signed reviewer genesis acceptance commitment" \
  "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32" \
  "$EXECUTION_POLICY_ANCHOR_REVIEWER_GENESIS_ACCEPTANCE_SHA256_BYTES32"
assert_address_equal "ExecutionPolicyAnchor empty writer" "$ZERO_ADDRESS" "$EXECUTION_POLICY_ANCHOR_INITIAL_WRITER"
assert_equal "ExecutionPolicyAnchor empty writer release" "$ZERO_BYTES32" "$EXECUTION_POLICY_ANCHOR_INITIAL_RELEASE"
assert_address_equal "ExecutionPolicyAnchor empty pending writer" "$ZERO_ADDRESS" "$EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_WRITER"
assert_equal "ExecutionPolicyAnchor empty pending release" "$ZERO_BYTES32" "$EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_RELEASE"
assert_equal "ExecutionPolicyAnchor empty pending activation" 0 "$EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_AT"
assert_equal "ExecutionPolicyAnchor rotations initially open" false "$EXECUTION_POLICY_ANCHOR_INITIAL_ROTATIONS_FROZEN"
assert_equal "ExecutionPolicyAnchor initially paused" true "$EXECUTION_POLICY_ANCHOR_INITIAL_PAUSED"
assert_equal "ExecutionPolicyAnchor initial sequence" 0 "$EXECUTION_POLICY_ANCHOR_INITIAL_SEQUENCE"
assert_equal "ExecutionPolicyAnchor initial head" "$ZERO_BYTES32" "$EXECUTION_POLICY_ANCHOR_INITIAL_HEAD"

echo
echo "== Synthetic Tinker exact release and per-operation witness =="
TINKER_RELEASE_MANAGER="$TEE_IDENTITY"
TINKER_RELEASE_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'computeComposeRoot(bytes32[])(bytes32)' "[$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH]" --rpc-url "$RPC_URL")"
TINKER_RELEASE_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'computeManagerRoot(address[])(bytes32)' "[$TINKER_RELEASE_MANAGER]" --rpc-url "$RPC_URL")"
TINKER_RELEASE_COMMITMENT="$(cast call "$ENCUMBRANCE_ADDRESS" \
  'computeReleasePolicyCommitment(bytes32,uint256,uint256,bytes32,uint256,bytes32,uint256)(bytes32)' \
  "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" \
  "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" \
  "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI" \
  "$TINKER_RELEASE_COMPOSE_ROOT" 1 "$TINKER_RELEASE_MANAGER_ROOT" 1 \
  --rpc-url "$RPC_URL")"
TINKER_PROPOSE_RELEASE_TX="$(
  send_tx tinker-propose-release "$DEPLOYMENT_OPERATOR" \
    "$ENCUMBRANCE_ADDRESS" \
    'proposeReleasePolicy(bytes32,uint256,uint256,bytes32[],address[])' \
    "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" \
    "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" \
    "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI" \
    "[$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH]" \
    "[$TINKER_RELEASE_MANAGER]"
)"
TINKER_RELEASE_ELIGIBLE_AT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyActivatesAt()(uint64)')"
assert_equal "Tinker pending release commitment" "$TINKER_RELEASE_COMMITMENT" "$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
assert_equal "Tinker pending compose root" "$TINKER_RELEASE_COMPOSE_ROOT" "$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
assert_equal "Tinker pending compose count" 1 "$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingComposeCount()(uint256)')"
assert_equal "Tinker pending manager root" "$TINKER_RELEASE_MANAGER_ROOT" "$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingManagerRoot()(bytes32)' --rpc-url "$RPC_URL")"
assert_equal "Tinker pending manager count" 1 "$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingManagerCount()(uint256)')"
if [ "$TINKER_RELEASE_ELIGIBLE_AT" -le "$(block_timestamp)" ]; then
  fail "Tinker phase A did not schedule a future review eligibility time"
fi
cast rpc anvil_setNextBlockTimestamp "$TINKER_RELEASE_ELIGIBLE_AT" --rpc-url "$RPC_URL" >/dev/null
cast rpc evm_mine --rpc-url "$RPC_URL" >/dev/null
TINKER_ACTIVATE_RELEASE_TX="$(
  send_tx tinker-activate-release "$DEPLOYMENT_OPERATOR" \
    "$ENCUMBRANCE_ADDRESS" 'activateAndFreezeReleasePolicy()'
)"

TINKER_FINAL_ACCOUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'accountCommitment()(bytes32)' --rpc-url "$RPC_URL")"
TINKER_FINAL_MAX_ADD="$(read_uint "$ENCUMBRANCE_ADDRESS" 'maxAddBalanceWei()(uint256)')"
TINKER_FINAL_MAX_SPEND="$(read_uint "$ENCUMBRANCE_ADDRESS" 'maxSpendWei()(uint256)')"
TINKER_FINAL_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'approvedComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
TINKER_FINAL_COMPOSE_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'approvedComposeCount()(uint256)')"
TINKER_FINAL_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'managerRoot()(bytes32)' --rpc-url "$RPC_URL")"
TINKER_FINAL_MANAGER_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'managerCount()(uint256)')"
TINKER_FINAL_RELEASE_COMMITMENT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
TINKER_FINAL_RELEASE_MAX_ADD="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseMaxAddBalanceWei()(uint256)')"
TINKER_FINAL_RELEASE_MAX_SPEND="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseMaxSpendWei()(uint256)')"
TINKER_FINAL_RELEASE_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
TINKER_FINAL_RELEASE_COMPOSE_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseComposeCount()(uint256)')"
TINKER_FINAL_RELEASE_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseManagerRoot()(bytes32)' --rpc-url "$RPC_URL")"
TINKER_FINAL_RELEASE_MANAGER_COUNT="$(read_uint "$ENCUMBRANCE_ADDRESS" 'releaseManagerCount()(uint256)')"
TINKER_FINAL_FROZEN="$(cast call "$ENCUMBRANCE_ADDRESS" 'releasePolicyFrozen()(bool)' --rpc-url "$RPC_URL")"
TINKER_FINAL_HALTED="$(cast call "$ENCUMBRANCE_ADDRESS" 'emergencyHalted()(bool)' --rpc-url "$RPC_URL")"

assert_equal "Tinker final account" "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" "$TINKER_FINAL_ACCOUNT"
assert_equal "Tinker final add-balance cap" "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" "$TINKER_FINAL_MAX_ADD"
assert_equal "Tinker final spend cap" "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI" "$TINKER_FINAL_MAX_SPEND"
assert_equal "Tinker final compose root" "$TINKER_RELEASE_COMPOSE_ROOT" "$TINKER_FINAL_COMPOSE_ROOT"
assert_equal "Tinker final compose count" 1 "$TINKER_FINAL_COMPOSE_COUNT"
assert_equal "Tinker final manager root" "$TINKER_RELEASE_MANAGER_ROOT" "$TINKER_FINAL_MANAGER_ROOT"
assert_equal "Tinker final manager count" 1 "$TINKER_FINAL_MANAGER_COUNT"
assert_equal "Tinker frozen baseline commitment" "$TINKER_RELEASE_COMMITMENT" "$TINKER_FINAL_RELEASE_COMMITMENT"
assert_equal "Tinker frozen baseline add-balance cap" "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" "$TINKER_FINAL_RELEASE_MAX_ADD"
assert_equal "Tinker frozen baseline spend cap" "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI" "$TINKER_FINAL_RELEASE_MAX_SPEND"
assert_equal "Tinker frozen baseline compose root" "$TINKER_RELEASE_COMPOSE_ROOT" "$TINKER_FINAL_RELEASE_COMPOSE_ROOT"
assert_equal "Tinker frozen baseline compose count" 1 "$TINKER_FINAL_RELEASE_COMPOSE_COUNT"
assert_equal "Tinker frozen baseline manager root" "$TINKER_RELEASE_MANAGER_ROOT" "$TINKER_FINAL_RELEASE_MANAGER_ROOT"
assert_equal "Tinker frozen baseline manager count" 1 "$TINKER_FINAL_RELEASE_MANAGER_COUNT"
assert_equal "Tinker final policy freeze" true "$TINKER_FINAL_FROZEN"
assert_equal "Tinker final halt" false "$TINKER_FINAL_HALTED"
assert_equal "Tinker cleared pending activation" 0 "$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyActivatesAt()(uint64)')"
assert_equal "Tinker cleared pending commitment" "$ZERO_BYTES32" "$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
assert_equal "Tinker cleared pending compose count" 0 "$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingComposeCount()(uint256)')"
assert_equal "Tinker cleared pending manager count" 0 "$(read_uint "$ENCUMBRANCE_ADDRESS" 'pendingManagerCount()(uint256)')"

# Two distinct operations may each use the full ceiling. This is deliberate
# evidence that the on-chain policy is a per-operation cap, not an account-wide
# escrow balance or cumulative budget.
TINKER_OPERATION_ONE="$(cast keccak 'dnai/local-rehearsal/tinker-operation/1')"
TINKER_OPERATION_TWO="$(cast keccak 'dnai/local-rehearsal/tinker-operation/2')"
TINKER_OPERATION_RECEIPT_ONE="$(cast keccak 'dnai/local-rehearsal/tinker-operation-receipt/1')"
TINKER_OPERATION_RECEIPT_TWO="$(cast keccak 'dnai/local-rehearsal/tinker-operation-receipt/2')"
TINKER_AUTHORIZE_ONE_TX="$(
  send_tx tinker-authorize-one "$TINKER_RELEASE_MANAGER" \
    "$ENCUMBRANCE_ADDRESS" 'authorizeOperation(bytes32,uint8,address,bytes32,uint256)' \
    "$TINKER_OPERATION_ONE" 1 "$BUYER" "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH" \
    "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI"
)"
TINKER_AUTHORIZE_TWO_TX="$(
  send_tx tinker-authorize-two "$TINKER_RELEASE_MANAGER" \
    "$ENCUMBRANCE_ADDRESS" 'authorizeOperation(bytes32,uint8,address,bytes32,uint256)' \
    "$TINKER_OPERATION_TWO" 1 "$BUYER" "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH" \
    "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI"
)"
TINKER_SETTLE_ONE_TX="$(
  send_tx tinker-settle-one "$TINKER_RELEASE_MANAGER" \
    "$ENCUMBRANCE_ADDRESS" 'settleOperation(bytes32,bool,bytes32)' \
    "$TINKER_OPERATION_ONE" true "$TINKER_OPERATION_RECEIPT_ONE"
)"
TINKER_SETTLE_TWO_TX="$(
  send_tx tinker-settle-two "$TINKER_RELEASE_MANAGER" \
    "$ENCUMBRANCE_ADDRESS" 'settleOperation(bytes32,bool,bytes32)' \
    "$TINKER_OPERATION_TWO" true "$TINKER_OPERATION_RECEIPT_TWO"
)"
TINKER_CONTRACT_BALANCE="$(cast balance "$ENCUMBRANCE_ADDRESS" --rpc-url "$RPC_URL")"
assert_equal "Tinker encumbrance remains non-custodial" 0 "$TINKER_CONTRACT_BALANCE"

echo
echo "== Synthetic ExecutionPolicyAnchor monotonic witness =="
EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT="$(cast keccak 'dnai/local-rehearsal/execution-policy-writer-release/v1')"
EXECUTION_POLICY_RESOURCE_HASH="$(cast keccak 'dnai/local-rehearsal/execution-policy-resource/v1')"
EXECUTION_POLICY_DECISION_HASH="$(cast keccak 'dnai/local-rehearsal/execution-policy-decision/v1')"
EXECUTION_POLICY_PROPOSE_WRITER_TX="$(
  send_tx policy-anchor-propose-writer "$DEPLOYMENT_OPERATOR" \
    "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
    'proposeWriter(address,bytes32)' \
    "$EXECUTION_POLICY_ANCHOR_WRITER" \
    "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT"
)"
cast rpc evm_increaseTime 172800 --rpc-url "$RPC_URL" >/dev/null
cast rpc evm_mine --rpc-url "$RPC_URL" >/dev/null
EXECUTION_POLICY_ACTIVATE_WRITER_TX="$(
  send_tx policy-anchor-activate-writer "$DEPLOYMENT_OPERATOR" \
    "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'activateWriter()'
)"
EXECUTION_POLICY_FREEZE_WRITER_TX="$(
  send_tx policy-anchor-freeze-writer "$DEPLOYMENT_OPERATOR" \
    "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'freezeWriterRotations()'
)"
EXECUTION_POLICY_UNPAUSE_TX="$(
  send_tx policy-anchor-unpause "$DEPLOYMENT_OPERATOR" \
    "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'setPaused(bool)' false
)"
EXECUTION_POLICY_ANCHOR_DECISION_TX="$(
  send_tx policy-anchor-decision "$EXECUTION_POLICY_ANCHOR_WRITER" \
    "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
    'anchorDecision(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)' \
    0 \
    "$ZERO_BYTES32" \
    "$EXECUTION_POLICY_RESOURCE_HASH" \
    "$ZERO_BYTES32" \
    "$EXECUTION_POLICY_DECISION_HASH" \
    "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT"
)"

EXECUTION_POLICY_FINAL_WRITER="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writer()(address)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_FINAL_RELEASE="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerReleaseCommitment()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_FINAL_FROZEN="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerRotationsFrozen()(bool)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_FINAL_PAUSED="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'paused()(bool)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_FINAL_SEQUENCE="$(read_uint "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalSequence()(uint256)')"
EXECUTION_POLICY_FINAL_HEAD="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalHead()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_FINAL_RESOURCE_HEAD="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'resourceDecisionHead(bytes32)(bytes32)' "$EXECUTION_POLICY_RESOURCE_HASH" --rpc-url "$RPC_URL")"
EXECUTION_POLICY_FINAL_RESOURCE_SEQUENCE="$(read_uint "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'resourceSequence(bytes32)(uint256)' "$EXECUTION_POLICY_RESOURCE_HASH")"
EXECUTION_POLICY_FINAL_DECISION_SEQUENCE="$(read_uint "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'decisionSequence(bytes32)(uint256)' "$EXECUTION_POLICY_DECISION_HASH")"

assert_address_equal "ExecutionPolicyAnchor final writer" "$EXECUTION_POLICY_ANCHOR_WRITER" "$EXECUTION_POLICY_FINAL_WRITER"
assert_equal "ExecutionPolicyAnchor final release" "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT" "$EXECUTION_POLICY_FINAL_RELEASE"
assert_equal "ExecutionPolicyAnchor final writer freeze" true "$EXECUTION_POLICY_FINAL_FROZEN"
assert_equal "ExecutionPolicyAnchor final pause" false "$EXECUTION_POLICY_FINAL_PAUSED"
assert_equal "ExecutionPolicyAnchor final sequence" 1 "$EXECUTION_POLICY_FINAL_SEQUENCE"
validate_bytes32 "ExecutionPolicyAnchor final global head" "$EXECUTION_POLICY_FINAL_HEAD"
assert_equal "ExecutionPolicyAnchor final resource head" "$EXECUTION_POLICY_DECISION_HASH" "$EXECUTION_POLICY_FINAL_RESOURCE_HEAD"
assert_equal "ExecutionPolicyAnchor final resource sequence" 1 "$EXECUTION_POLICY_FINAL_RESOURCE_SEQUENCE"
assert_equal "ExecutionPolicyAnchor final decision sequence" 1 "$EXECUTION_POLICY_FINAL_DECISION_SEQUENCE"

echo
echo "== Synthetic DiligenceRoom accepted lifecycle =="
DILIGENCE_COMPOSE_HASH="$(cast keccak 'dnai/local-rehearsal/diligence-compose/v1')"
DILIGENCE_EVALUATOR_POLICY_1="$(cast keccak 'dnai/local-rehearsal/diligence-evaluator-policy/1/v1')"
DILIGENCE_EVALUATOR_POLICY_2="$(cast keccak 'dnai/local-rehearsal/diligence-evaluator-policy/2/v1')"
DILIGENCE_EVALUATOR_POLICY_3="$(cast keccak 'dnai/local-rehearsal/diligence-evaluator-policy/3/v1')"
DILIGENCE_EVALUATOR_POLICIES="[$DILIGENCE_EVALUATOR_POLICY_1,$DILIGENCE_EVALUATOR_POLICY_2,$DILIGENCE_EVALUATOR_POLICY_3]"
DILIGENCE_EXPECTED_EVALUATOR_POLICY_ROOT="$(
  cast call \
    "$DILIGENCE_ADDRESS" \
    'computeEvaluatorPolicySetRoot(bytes32[3])(bytes32)' \
    "$DILIGENCE_EVALUATOR_POLICIES" \
    --rpc-url "$RPC_URL"
)"
validate_bytes32 "Diligence evaluator policy-set root" "$DILIGENCE_EXPECTED_EVALUATOR_POLICY_ROOT"
ARTIFACT_COMMITMENT="$(cast keccak 'dnai/local-rehearsal/private-artifact-commitment/v1')"
RESERVE_PRICE=500000000000000000
BUDGET_CAP=2000000000000000000
DILIGENCE_PROPOSE_COMPOSE_TX="$(
  send_tx diligence-propose-compose "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'proposeComposeHash(bytes32)' "$DILIGENCE_COMPOSE_HASH"
)"
DILIGENCE_PROPOSE_EVALUATOR_POLICY_SET_TX="$(
  send_tx diligence-propose-evaluator-policy-set "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" \
    'proposeEvaluatorPolicySet(bytes32[3])' \
    "$DILIGENCE_EVALUATOR_POLICIES"
)"
DILIGENCE_PROPOSE_RESULT_VERIFIER_TX="$(
  send_tx diligence-propose-result-verifier "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'proposeResultVerifier(address)' "$DILIGENCE_RESULT_VERIFIER"
)"
DILIGENCE_PROPOSE_ATTESTATION_TX="$(
  send_tx diligence-propose-attestation "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'proposeAttestationBinding(address,bytes32)' \
    "$DILIGENCE_ATTESTATION_VERIFIER" "$DILIGENCE_QVL_RELEASE_POLICY_HASH"
)"
cast rpc evm_increaseTime 172800 --rpc-url "$RPC_URL" >/dev/null
cast rpc evm_mine --rpc-url "$RPC_URL" >/dev/null
DILIGENCE_ACTIVATE_COMPOSE_TX="$(
  send_tx diligence-activate-compose "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'activateComposeHash(bytes32)' "$DILIGENCE_COMPOSE_HASH"
)"
DILIGENCE_ACTIVATE_EVALUATOR_POLICY_SET_TX="$(
  send_tx diligence-activate-evaluator-policy-set "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" \
    'activateEvaluatorPolicySet(bytes32[3])' \
    "$DILIGENCE_EVALUATOR_POLICIES"
)"
DILIGENCE_FREEZE_EVALUATOR_POLICY_SET_TX="$(
  send_tx diligence-freeze-evaluator-policy-set "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'freezeEvaluatorPolicySet()'
)"
DILIGENCE_ACTIVATE_RESULT_VERIFIER_TX="$(
  send_tx diligence-activate-result-verifier "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'activateResultVerifier()'
)"
DILIGENCE_FREEZE_RESULT_VERIFIER_TX="$(
  send_tx diligence-freeze-result-verifier "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'freezeResultVerifier()'
)"
DILIGENCE_ACTIVATE_ATTESTATION_TX="$(
  send_tx diligence-activate-attestation "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'activateAttestationBinding()'
)"
DILIGENCE_FREEZE_ATTESTATION_TX="$(
  send_tx diligence-freeze-attestation "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'freezeAttestationBinding()'
)"
DILIGENCE_PROPOSE_IDENTITY_TX="$(
  send_tx diligence-propose-identity "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'proposeTeeIdentity(address,bytes32)' "$TEE_IDENTITY" "$DILIGENCE_COMPOSE_HASH"
)"
cast rpc evm_increaseTime 172800 --rpc-url "$RPC_URL" >/dev/null
cast rpc evm_mine --rpc-url "$RPC_URL" >/dev/null
DILIGENCE_ACTIVATE_IDENTITY_TX="$(
  send_tx diligence-activate-identity "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'activateTeeIdentity(address)' "$TEE_IDENTITY"
)"
DILIGENCE_FREEZE_COMPOSE_TX="$(
  send_tx diligence-freeze-compose "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'freezeComposeAdditions()'
)"
DILIGENCE_FREEZE_IDENTITY_TX="$(
  send_tx diligence-freeze-identity "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'freezeTeeIdentityAdditions()'
)"
DILIGENCE_PROPOSE_DEVELOPER_TX="$(
  send_tx diligence-propose-governance-controller "$DEPLOYMENT_OPERATOR" \
    "$DILIGENCE_ADDRESS" 'proposeDeveloper(address)' "$DILIGENCE_GOVERNANCE_CONTROLLER"
)"
cast rpc evm_increaseTime 172800 --rpc-url "$RPC_URL" >/dev/null
cast rpc evm_mine --rpc-url "$RPC_URL" >/dev/null
DILIGENCE_ACCEPT_DEVELOPER_TX="$(
  send_tx diligence-accept-governance-controller "$DILIGENCE_GOVERNANCE_CONTROLLER" \
    "$DILIGENCE_ADDRESS" 'acceptDeveloper()'
)"
DILIGENCE_FINAL_DEVELOPER="$(cast call "$DILIGENCE_ADDRESS" 'developer()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_PENDING_DEVELOPER="$(cast call "$DILIGENCE_ADDRESS" 'pendingDeveloper()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_ATTESTATION_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'attestationVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_ATTESTATION_POLICY_HASH="$(cast call "$DILIGENCE_ADDRESS" 'attestationReleasePolicyHash()(bytes32)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_ATTESTATION_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'attestationBindingFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_RESULT_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'resultVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_RESULT_VERIFIER_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'resultVerifierFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_EVALUATOR_POLICY_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'approvedEvaluatorPolicyCount()(uint256)')"
DILIGENCE_FINAL_PENDING_EVALUATOR_POLICY_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingEvaluatorPolicyCount()(uint256)')"
DILIGENCE_FINAL_EVALUATOR_POLICY_ROOT="$(cast call "$DILIGENCE_ADDRESS" 'evaluatorPolicySetRoot()(bytes32)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_EVALUATOR_POLICY_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'evaluatorPolicySetFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_COMPOSE_APPROVED="$(
  cast call "$DILIGENCE_ADDRESS" 'approvedComposeHashes(bytes32)(bool)' "$DILIGENCE_COMPOSE_HASH" --rpc-url "$RPC_URL"
)"
DILIGENCE_FINAL_APPROVED_COMPOSE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'approvedComposeCount()(uint256)')"
DILIGENCE_FINAL_PENDING_COMPOSE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingComposeCount()(uint256)')"
DILIGENCE_FINAL_COMPOSE_ADDITIONS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'composeAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_FINAL_TEE_COMPOSE_HASH="$(
  cast call "$DILIGENCE_ADDRESS" 'teeIdentityComposeHash(address)(bytes32)' "$TEE_IDENTITY" --rpc-url "$RPC_URL"
)"
DILIGENCE_FINAL_APPROVED_TEE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'approvedTeeIdentityCount()(uint256)')"
DILIGENCE_FINAL_PENDING_TEE_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'pendingTeeIdentityCount()(uint256)')"
DILIGENCE_FINAL_TEE_ADDITIONS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'teeIdentityAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
assert_address_equal "DiligenceRoom final result verifier" "$DILIGENCE_RESULT_VERIFIER" "$DILIGENCE_FINAL_RESULT_VERIFIER"
assert_address_equal \
  "DiligenceRoom final governance controller" \
  "$DILIGENCE_GOVERNANCE_CONTROLLER" \
  "$DILIGENCE_FINAL_DEVELOPER"
assert_address_equal \
  "DiligenceRoom final pending developer" \
  "$ZERO_ADDRESS" \
  "$DILIGENCE_FINAL_PENDING_DEVELOPER"
assert_equal "DiligenceRoom final result-verifier freeze" true "$DILIGENCE_FINAL_RESULT_VERIFIER_FROZEN"
assert_address_equal "DiligenceRoom final attestation verifier" "$DILIGENCE_ATTESTATION_VERIFIER" "$DILIGENCE_FINAL_ATTESTATION_VERIFIER"
assert_equal "DiligenceRoom final attestation policy" "$DILIGENCE_QVL_RELEASE_POLICY_HASH" "$DILIGENCE_FINAL_ATTESTATION_POLICY_HASH"
assert_equal "DiligenceRoom final attestation freeze" true "$DILIGENCE_FINAL_ATTESTATION_FROZEN"
assert_equal "DiligenceRoom exact evaluator policy count" 3 "$DILIGENCE_FINAL_EVALUATOR_POLICY_COUNT"
assert_equal "DiligenceRoom pending evaluator policy count" 0 "$DILIGENCE_FINAL_PENDING_EVALUATOR_POLICY_COUNT"
assert_equal "DiligenceRoom evaluator policy-set root" "$DILIGENCE_EXPECTED_EVALUATOR_POLICY_ROOT" "$DILIGENCE_FINAL_EVALUATOR_POLICY_ROOT"
assert_equal "DiligenceRoom evaluator policy-set freeze" true "$DILIGENCE_FINAL_EVALUATOR_POLICY_FROZEN"
assert_equal "DiligenceRoom synthetic compose approval" true "$DILIGENCE_FINAL_COMPOSE_APPROVED"
assert_equal "DiligenceRoom exact compose admission count" 1 "$DILIGENCE_FINAL_APPROVED_COMPOSE_COUNT"
assert_equal "DiligenceRoom pending compose admission count" 0 "$DILIGENCE_FINAL_PENDING_COMPOSE_COUNT"
assert_equal "DiligenceRoom compose admission freeze" true "$DILIGENCE_FINAL_COMPOSE_ADDITIONS_FROZEN"
assert_equal "DiligenceRoom synthetic TEE identity binding" "$DILIGENCE_COMPOSE_HASH" "$DILIGENCE_FINAL_TEE_COMPOSE_HASH"
assert_equal "DiligenceRoom exact TEE identity count" 1 "$DILIGENCE_FINAL_APPROVED_TEE_COUNT"
assert_equal "DiligenceRoom pending TEE identity count" 0 "$DILIGENCE_FINAL_PENDING_TEE_COUNT"
assert_equal "DiligenceRoom TEE identity freeze" true "$DILIGENCE_FINAL_TEE_ADDITIONS_FROZEN"
for evaluator_policy in \
  "$DILIGENCE_EVALUATOR_POLICY_1" \
  "$DILIGENCE_EVALUATOR_POLICY_2" \
  "$DILIGENCE_EVALUATOR_POLICY_3"; do
  evaluator_policy_approved="$(
    cast call \
      "$DILIGENCE_ADDRESS" \
      'approvedEvaluatorPolicies(bytes32)(bool)' \
      "$evaluator_policy" \
      --rpc-url "$RPC_URL"
  )"
  assert_equal "DiligenceRoom approved evaluator policy $evaluator_policy" true "$evaluator_policy_approved"
done
EXPIRY="$(( $(block_timestamp) + 86400 ))"
DILIGENCE_CREATE_TX="$(
  send_tx diligence-create "$SELLER" \
    "$DILIGENCE_ADDRESS" \
    'createDeal(uint256,uint256,bytes32,address)' \
    "$RESERVE_PRICE" \
    "$EXPIRY" \
    "$ARTIFACT_COMMITMENT" \
    "$TEE_IDENTITY"
)"
DILIGENCE_FUND_TX="$(
  send_tx diligence-fund "$BUYER" \
    "$DILIGENCE_ADDRESS" \
    'fundDeal(uint256,bytes32)' \
    0 \
    "$DILIGENCE_EVALUATOR_POLICY_1" \
    --value "$BUDGET_CAP"
)"

COMPUTE_COST="$(read_uint "$DILIGENCE_ADDRESS" 'policyComputeCost(uint256)(uint256)' 0)"
AUTHORIZATION_EXPIRY="$(( $(block_timestamp) + 300 ))"
AUTHORIZATION_DIGEST="$(
  cast call \
    "$DILIGENCE_ADDRESS" \
    'resultAuthorizationDigest(uint256,bytes32,uint8,uint256,uint256)(bytes32)' \
    0 \
    "$DILIGENCE_COMPOSE_HASH" \
    4 \
    "$COMPUTE_COST" \
    "$AUTHORIZATION_EXPIRY" \
    --rpc-url "$RPC_URL"
)"
validate_bytes32 "Diligence result authorization digest" "$AUTHORIZATION_DIGEST"
VERIFIER_SIGNATURE="$(
  cast rpc eth_sign "$DILIGENCE_RESULT_VERIFIER" "$AUTHORIZATION_DIGEST" --rpc-url "$RPC_URL" | jq -r '.'
)"
if [[ ! "$VERIFIER_SIGNATURE" =~ ^0x[0-9a-fA-F]{130}$ ]]; then
  fail "Anvil result-verifier signature is not a 65-byte signature"
fi
DILIGENCE_ATTESTATION_EVIDENCE_HASH="$(cast keccak 'dnai/local-rehearsal/diligence-attestation-evidence/v1')"
ATTESTATION_AUTHORIZATION_EXPIRY="$AUTHORIZATION_EXPIRY"
ATTESTATION_AUTHORIZATION_DIGEST="$(
  cast call \
    "$DILIGENCE_ADDRESS" \
    'attestationAuthorizationDigest(uint256,bytes32,uint8,uint256,bytes32,uint256)(bytes32)' \
    0 \
    "$DILIGENCE_COMPOSE_HASH" \
    4 \
    "$COMPUTE_COST" \
    "$DILIGENCE_ATTESTATION_EVIDENCE_HASH" \
    "$ATTESTATION_AUTHORIZATION_EXPIRY" \
    --rpc-url "$RPC_URL"
)"
validate_bytes32 "Diligence attestation authorization digest" "$ATTESTATION_AUTHORIZATION_DIGEST"
ATTESTATION_VERIFIER_SIGNATURE="$(
  cast rpc \
    eth_sign \
    "$DILIGENCE_ATTESTATION_VERIFIER" \
    "$ATTESTATION_AUTHORIZATION_DIGEST" \
    --rpc-url "$RPC_URL" | jq -r '.'
)"
if [[ ! "$ATTESTATION_VERIFIER_SIGNATURE" =~ ^0x[0-9a-fA-F]{130}$ ]]; then
  fail "Anvil attestation-verifier signature is not a 65-byte signature"
fi

DILIGENCE_SUBMIT_TX="$(
  send_tx diligence-submit "$TEE_IDENTITY" \
    "$DILIGENCE_ADDRESS" \
    'submitResult(uint256,uint8,uint256,bytes32,uint256,bytes32,uint256,bytes,bytes)' \
    0 \
    4 \
    "$COMPUTE_COST" \
    "$DILIGENCE_COMPOSE_HASH" \
    "$AUTHORIZATION_EXPIRY" \
    "$DILIGENCE_ATTESTATION_EVIDENCE_HASH" \
    "$ATTESTATION_AUTHORIZATION_EXPIRY" \
    "$VERIFIER_SIGNATURE" \
    "$ATTESTATION_VERIFIER_SIGNATURE"
)"
DILIGENCE_ACCEPT_TX="$(
  send_tx diligence-accept "$BUYER" \
    "$DILIGENCE_ADDRESS" 'acceptDeal(uint256,uint256)' 0 "$RESERVE_PRICE"
)"

DEAL_FIELDS="$(
  cast call \
    "$DILIGENCE_ADDRESS" \
    'getDeal(uint256)(address,address,uint256,uint256,uint256,uint8,bytes32,address,uint8,uint256,uint256,bytes32,bytes32,address,bytes32,bytes32,uint256,uint256)' \
    0 \
    --rpc-url "$RPC_URL"
)"
DEAL_STATE="$(printf '%s\n' "$DEAL_FIELDS" | sed -n '6p' | awk '{print $1}')"
DEAL_EVALUATOR_POLICY="$(printf '%s\n' "$DEAL_FIELDS" | sed -n '15p' | awk '{print $1}')"
DEAL_ATTESTATION_EVIDENCE_HASH="$(printf '%s\n' "$DEAL_FIELDS" | sed -n '16p' | awk '{print $1}')"
DEAL_COUNT="$(read_uint "$DILIGENCE_ADDRESS" 'dealCount()(uint256)')"
EXPECTED_FEE="$((COMPUTE_COST / 100))"
EXPECTED_DEVELOPER_PAYMENT="$((COMPUTE_COST + EXPECTED_FEE))"
EXPECTED_BUYER_REFUND="$((BUDGET_CAP - RESERVE_PRICE - EXPECTED_DEVELOPER_PAYMENT))"
SELLER_PENDING="$(
  read_uint "$DILIGENCE_ADDRESS" 'pendingWithdrawals(address,address)(uint256)' "$ZERO_ADDRESS" "$SELLER"
)"
DEVELOPER_PENDING="$(
  read_uint "$DILIGENCE_ADDRESS" 'pendingWithdrawals(address,address)(uint256)' "$ZERO_ADDRESS" "$DILIGENCE_GOVERNANCE_CONTROLLER"
)"
BUYER_PENDING="$(
  read_uint "$DILIGENCE_ADDRESS" 'pendingWithdrawals(address,address)(uint256)' "$ZERO_ADDRESS" "$BUYER"
)"

assert_equal "Diligence deal count" 1 "$DEAL_COUNT"
assert_equal "Diligence accepted state" 3 "$DEAL_STATE"
assert_equal "Diligence deal evaluator policy" "$DILIGENCE_EVALUATOR_POLICY_1" "$DEAL_EVALUATOR_POLICY"
assert_equal "Diligence deal attestation evidence" "$DILIGENCE_ATTESTATION_EVIDENCE_HASH" "$DEAL_ATTESTATION_EVIDENCE_HASH"
assert_equal "Diligence seller accrual" "$RESERVE_PRICE" "$SELLER_PENDING"
assert_equal "Diligence developer accrual" "$EXPECTED_DEVELOPER_PAYMENT" "$DEVELOPER_PENDING"
assert_equal "Diligence buyer refund accrual" "$EXPECTED_BUYER_REFUND" "$BUYER_PENDING"

echo
echo "== Synthetic ChallengeRegistry version/freeze/open behavior =="
CHALLENGE_METADATA_HASH_V1="$(cast keccak 'dnai/local-rehearsal/challenge-metadata/v1')"
CHALLENGE_SEALED_HASH_V1="$(cast keccak 'dnai/local-rehearsal/challenge-sealed-artifact/v1')"
CHALLENGE_EVALUATOR_HASH_V1="$(cast keccak 'dnai/local-rehearsal/challenge-evaluator/v1')"
CHALLENGE_RELEASE_HASH_V1="$(cast keccak 'dnai/local-rehearsal/challenge-release-policy/v1')"
CHALLENGE_METADATA_HASH_V2="$(cast keccak 'dnai/local-rehearsal/challenge-metadata/v2')"
CHALLENGE_SEALED_HASH_V2="$(cast keccak 'dnai/local-rehearsal/challenge-sealed-artifact/v2')"
CHALLENGE_EVALUATOR_HASH_V2="$(cast keccak 'dnai/local-rehearsal/challenge-evaluator/v2')"
CHALLENGE_RELEASE_HASH_V2="$(cast keccak 'dnai/local-rehearsal/challenge-release-policy/v2')"
CHALLENGE_VERSION_V1="(ipfs://local-only/dnai-challenge-v1,$CHALLENGE_METADATA_HASH_V1,$CHALLENGE_SEALED_HASH_V1,$CHALLENGE_EVALUATOR_HASH_V1,$CHALLENGE_RELEASE_HASH_V1)"
CHALLENGE_VERSION_V2="(ipfs://local-only/dnai-challenge-v2,$CHALLENGE_METADATA_HASH_V2,$CHALLENGE_SEALED_HASH_V2,$CHALLENGE_EVALUATOR_HASH_V2,$CHALLENGE_RELEASE_HASH_V2)"

CHALLENGE_SET_REGISTRAR_TX="$(
  send_tx challenge-set-registrar "$DEPLOYMENT_OPERATOR" \
    "$CHALLENGE_ADDRESS" 'setRegistrar(address,bool)' "$SELLER" true
)"
CHALLENGE_CREATE_TX="$(
  send_tx challenge-create "$SELLER" \
    "$CHALLENGE_ADDRESS" \
    'createChallenge(address,(string,bytes32,bytes32,bytes32,bytes32))' \
    "$CHALLENGE_CONTROLLER" \
    "$CHALLENGE_VERSION_V1"
)"
CHALLENGE_ADD_VERSION_TX="$(
  send_tx challenge-add-version "$CHALLENGE_CONTROLLER" \
    "$CHALLENGE_ADDRESS" \
    'addVersion(uint256,(string,bytes32,bytes32,bytes32,bytes32))' \
    1 \
    "$CHALLENGE_VERSION_V2"
)"
CHALLENGE_PUBLISH_BLOCK="$(receipt_block challenge-add-version)"
CHALLENGE_REVIEW_ELIGIBLE_AT="$(read_uint "$CHALLENGE_ADDRESS" 'reviewEligibleAt(uint256)(uint64)' 1)"
CHALLENGE_MIN_REVIEW_DELAY="$(read_uint "$CHALLENGE_ADDRESS" 'MIN_VERSION_REVIEW_DELAY()(uint64)')"
assert_equal "Challenge minimum version review delay" 172800 "$CHALLENGE_MIN_REVIEW_DELAY"
if [ "$CHALLENGE_REVIEW_ELIGIBLE_AT" -le "$(block_timestamp)" ]; then
  fail "Challenge Phase A did not schedule a future review eligibility time"
fi
echo "Challenge Phase A published version 2 in block $CHALLENGE_PUBLISH_BLOCK; review eligible at $CHALLENGE_REVIEW_ELIGIBLE_AT."
cast rpc anvil_setNextBlockTimestamp "$CHALLENGE_REVIEW_ELIGIBLE_AT" --rpc-url "$RPC_URL" >/dev/null
cast rpc evm_mine --rpc-url "$RPC_URL" >/dev/null
CHALLENGE_FREEZE_TX="$(
  send_tx challenge-freeze "$CHALLENGE_CONTROLLER" \
    "$CHALLENGE_ADDRESS" 'freezeChallengeConfiguration(uint256)' 1
)"
CHALLENGE_FREEZE_BLOCK="$(receipt_block challenge-freeze)"
CHALLENGE_OPEN_TX="$(
  send_tx challenge-open "$CHALLENGE_CONTROLLER" \
    "$CHALLENGE_ADDRESS" 'setLifecycle(uint256,uint8)' 1 1
)"
CHALLENGE_OPEN_BLOCK="$(receipt_block challenge-open)"

CHALLENGE_FIELDS="$(
  cast call \
    "$CHALLENGE_ADDRESS" \
    'getChallenge(uint256)(address,address,uint8,uint64,uint64,uint32,bool,bool)' \
    1 \
    --rpc-url "$RPC_URL"
)"
CHALLENGE_FINAL_CONTROLLER="$(printf '%s\n' "$CHALLENGE_FIELDS" | sed -n '1p' | awk '{print $1}')"
CHALLENGE_FINAL_LIFECYCLE="$(printf '%s\n' "$CHALLENGE_FIELDS" | sed -n '3p' | awk '{print $1}')"
CHALLENGE_FINAL_VERSION="$(printf '%s\n' "$CHALLENGE_FIELDS" | sed -n '6p' | awk '{print $1}')"
CHALLENGE_FINAL_PAUSED="$(printf '%s\n' "$CHALLENGE_FIELDS" | sed -n '7p' | awk '{print $1}')"
CHALLENGE_FINAL_FROZEN="$(printf '%s\n' "$CHALLENGE_FIELDS" | sed -n '8p' | awk '{print $1}')"
CHALLENGE_FINAL_COUNT="$(read_uint "$CHALLENGE_ADDRESS" 'challengeCount()(uint256)')"
CHALLENGE_BALANCE="$(cast balance "$CHALLENGE_ADDRESS" --rpc-url "$RPC_URL")"

assert_address_equal "Challenge controller" "$CHALLENGE_CONTROLLER" "$CHALLENGE_FINAL_CONTROLLER"
assert_equal "Challenge open lifecycle" 1 "$CHALLENGE_FINAL_LIFECYCLE"
assert_equal "Challenge immutable latest version" 2 "$CHALLENGE_FINAL_VERSION"
assert_equal "Challenge pause state" false "$CHALLENGE_FINAL_PAUSED"
assert_equal "Challenge configuration freeze" true "$CHALLENGE_FINAL_FROZEN"
assert_equal "Challenge final count" 1 "$CHALLENGE_FINAL_COUNT"
assert_equal "Challenge non-custodial balance" 0 "$CHALLENGE_BALANCE"

echo
echo "== Build explicitly local manifest evidence =="
DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
SOURCE_TREE_CLEAN=true
if [ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]; then
  SOURCE_TREE_CLEAN=false
fi
PRODUCTION_SHAPE_MANIFEST="$EVIDENCE_DIR/.production-manifest-shape.tmp.json"
EVIDENCE_MANIFEST="$EVIDENCE_DIR/local-ephemeral-rehearsal.json"

jq -n '{}' | jq \
  --arg deployedAt "$DEPLOYED_AT" \
  --arg operator "$DEPLOYMENT_OPERATOR" \
  --arg verifier "$DILIGENCE_VERIFIER" \
  --arg sourceCommit "$SOURCE_COMMIT" \
  --arg deploymentIntentSha256 "$DEPLOYMENT_INTENT_SHA256" \
  --arg reviewerAuthorityGenesisAcceptanceSha256 "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256" \
  --argjson deploymentReviewEnvelopeSha256 null \
  --argjson deploymentReviewEvidenceSha256 null \
  --argjson deploymentReceipts "$DEPLOYMENT_RECEIPTS" \
  --argjson broadcastTransactions "$BROADCAST_TRANSACTIONS" \
  --arg broadcastTransactionsSha256 "$BROADCAST_TRANSACTIONS_SHA256" \
  --arg diligence "$DILIGENCE_ADDRESS" \
  --arg diligenceTx "$DILIGENCE_TX" \
  --arg diligenceRuntimeCodeHash "$DILIGENCE_RUNTIME_CODE_HASH" \
  --arg diligenceDeveloper "$DILIGENCE_DEVELOPER" \
  --arg diligenceInitialDeveloper "$DILIGENCE_INITIAL_DEVELOPER" \
  --arg diligenceGovernanceController "$DILIGENCE_GOVERNANCE_CONTROLLER" \
  --arg diligenceReleaseGovernanceController "$DILIGENCE_RELEASE_GOVERNANCE_CONTROLLER" \
  --arg diligenceProtocolFeeRecipient "$DILIGENCE_PROTOCOL_FEE_RECIPIENT" \
  --arg diligencePendingDeveloper "$DILIGENCE_PENDING_DEVELOPER" \
  --arg diligencePendingDeveloperAt "$DILIGENCE_PENDING_DEVELOPER_AT" \
  --arg diligenceDeveloperTransferDelay "$DILIGENCE_DEVELOPER_TRANSFER_DELAY" \
  --argjson diligenceProductionRelease "$DILIGENCE_PRODUCTION_RELEASE" \
  --arg diligenceDealCount "$DILIGENCE_DEAL_COUNT" \
  --arg diligencePendingVerifier "$DILIGENCE_INITIAL_PENDING_VERIFIER" \
  --arg diligencePendingVerifierAt "$DILIGENCE_INITIAL_PENDING_VERIFIER_AT" \
  --argjson diligenceVerifierFrozen "$DILIGENCE_INITIAL_VERIFIER_FROZEN" \
  --arg diligenceAttestationVerifier "$DILIGENCE_INITIAL_ATTESTATION_VERIFIER" \
  --arg diligenceAttestationPolicyHash "$DILIGENCE_INITIAL_ATTESTATION_POLICY_HASH" \
  --arg diligencePendingAttestationVerifier "$DILIGENCE_INITIAL_PENDING_ATTESTATION_VERIFIER" \
  --arg diligencePendingAttestationPolicyHash "$DILIGENCE_INITIAL_PENDING_ATTESTATION_POLICY_HASH" \
  --arg diligencePendingAttestationAt "$DILIGENCE_INITIAL_PENDING_ATTESTATION_AT" \
  --argjson diligenceAttestationBindingFrozen "$DILIGENCE_INITIAL_ATTESTATION_FROZEN" \
  --arg diligenceEvaluatorPoliciesAbi "$DILIGENCE_INITIAL_EVALUATOR_POLICIES_ABI" \
  --arg diligenceApprovedEvaluatorPolicyCount "$DILIGENCE_INITIAL_APPROVED_EVALUATOR_POLICY_COUNT" \
  --arg diligencePendingEvaluatorPolicyCount "$DILIGENCE_INITIAL_PENDING_EVALUATOR_POLICY_COUNT" \
  --arg diligenceEvaluatorPolicySetRoot "$DILIGENCE_INITIAL_EVALUATOR_POLICY_SET_ROOT" \
  --argjson diligenceEvaluatorPolicySetFrozen "$DILIGENCE_INITIAL_EVALUATOR_POLICY_SET_FROZEN" \
  --arg diligenceRequiredEvaluatorPolicyCount "$DILIGENCE_REQUIRED_EVALUATOR_POLICY_COUNT" \
  --argjson diligenceComposeRequired "$DILIGENCE_COMPOSE_REQUIRED" \
  --argjson diligenceIdentityRequired "$DILIGENCE_IDENTITY_REQUIRED" \
  --argjson diligenceApprovalRequirementsFrozen "$DILIGENCE_APPROVAL_REQUIREMENTS_FROZEN" \
  --arg diligenceApprovedComposeCount "$DILIGENCE_APPROVED_COMPOSE_COUNT" \
  --arg diligenceApprovedTeeCount "$DILIGENCE_APPROVED_TEE_COUNT" \
  --arg diligencePendingComposeCount "$DILIGENCE_PENDING_COMPOSE_COUNT" \
  --arg diligencePendingTeeCount "$DILIGENCE_PENDING_TEE_COUNT" \
  --argjson diligenceComposeAdditionsFrozen "$DILIGENCE_COMPOSE_ADDITIONS_FROZEN" \
  --argjson diligenceTeeAdditionsFrozen "$DILIGENCE_TEE_ADDITIONS_FROZEN" \
  --arg diligenceFeeBps "$DILIGENCE_FEE_BPS" \
  --argjson diligenceFeeBpsFrozen "$DILIGENCE_FEE_BPS_FROZEN" \
  --arg diligenceComputeSettlementBps "$DILIGENCE_COMPUTE_SETTLEMENT_BPS" \
  --argjson diligenceComputeSettlementPolicyEnabled "$DILIGENCE_COMPUTE_SETTLEMENT_POLICY_ENABLED" \
  --arg encumbrance "$ENCUMBRANCE_ADDRESS" \
  --arg encumbranceTx "$ENCUMBRANCE_TX" \
  --arg encumbranceRuntimeCodeHash "$ENCUMBRANCE_RUNTIME_CODE_HASH" \
  --arg encumbrancePendingOwner "$ENCUMBRANCE_PENDING_OWNER" \
  --arg accountCommitment "$ENCUMBRANCE_ACCOUNT" \
  --arg maxAddBalanceWei "$ENCUMBRANCE_MAX_ADD" \
  --arg maxSpendWei "$ENCUMBRANCE_MAX_SPEND" \
  --arg encumbranceComposeRoot "$ENCUMBRANCE_COMPOSE_ROOT" \
  --arg encumbranceComposeCount "$ENCUMBRANCE_COMPOSE_COUNT" \
  --arg encumbranceManagerRoot "$ENCUMBRANCE_MANAGER_ROOT" \
  --arg encumbranceManagerCount "$ENCUMBRANCE_MANAGER_COUNT" \
  --arg encumbranceReleaseCommitment "$ENCUMBRANCE_RELEASE_COMMITMENT" \
  --arg encumbranceReleaseMaxAddBalanceWei "$ENCUMBRANCE_RELEASE_MAX_ADD" \
  --arg encumbranceReleaseMaxSpendWei "$ENCUMBRANCE_RELEASE_MAX_SPEND" \
  --arg encumbranceReleaseComposeRoot "$ENCUMBRANCE_RELEASE_COMPOSE_ROOT" \
  --arg encumbranceReleaseComposeCount "$ENCUMBRANCE_RELEASE_COMPOSE_COUNT" \
  --arg encumbranceReleaseManagerRoot "$ENCUMBRANCE_RELEASE_MANAGER_ROOT" \
  --arg encumbranceReleaseManagerCount "$ENCUMBRANCE_RELEASE_MANAGER_COUNT" \
  --arg encumbrancePendingAccountCommitment "$ENCUMBRANCE_PENDING_ACCOUNT" \
  --arg encumbrancePendingMaxAddBalanceWei "$ENCUMBRANCE_PENDING_MAX_ADD" \
  --arg encumbrancePendingMaxSpendWei "$ENCUMBRANCE_PENDING_MAX_SPEND" \
  --arg encumbrancePendingComposeRoot "$ENCUMBRANCE_PENDING_COMPOSE_ROOT" \
  --arg encumbrancePendingManagerRoot "$ENCUMBRANCE_PENDING_MANAGER_ROOT" \
  --arg encumbrancePendingCommitment "$ENCUMBRANCE_PENDING_COMMITMENT" \
  --arg encumbrancePendingAt "$ENCUMBRANCE_PENDING_AT" \
  --arg encumbrancePendingComposeCount "$ENCUMBRANCE_PENDING_COMPOSE_COUNT" \
  --arg encumbrancePendingManagerCount "$ENCUMBRANCE_PENDING_MANAGER_COUNT" \
  --argjson encumbranceReleasePolicyFrozen "$ENCUMBRANCE_POLICY_FROZEN" \
  --argjson encumbranceEmergencyHalted "$ENCUMBRANCE_EMERGENCY_HALTED" \
  --arg royalty "$ROYALTY_ADDRESS" \
  --arg royaltyTx "$ROYALTY_TX" \
  --arg royaltyRuntimeCodeHash "$ROYALTY_RUNTIME_CODE_HASH" \
  --arg royaltyOwner "$ROYALTY_OWNER" \
  --arg royaltyPendingOwner "$ROYALTY_PENDING_OWNER" \
  --argjson royaltyPaused "$ROYALTY_PAUSED" \
  --arg royaltySettlementVerifier "$ROYALTY_SETTLEMENT_VERIFIER" \
  --arg royaltyQvlVerifier "$ROYALTY_QVL_VERIFIER" \
  --arg royaltyExecutionPolicyAnchor "$ROYALTY_EXECUTION_POLICY_ANCHOR" \
  --arg royaltyAnchorWriterRelease "$ROYALTY_ANCHOR_WRITER_RELEASE" \
  --arg royaltyReleasePolicy "$ROYALTY_RELEASE_POLICY" \
  --arg royaltyAuthorityNonce "$ROYALTY_AUTHORITY_NONCE" \
  --arg royaltyPendingAuthorityAt "$ROYALTY_PENDING_AUTHORITY_AT" \
  --arg challenge "$CHALLENGE_ADDRESS" \
  --arg challengeTx "$CHALLENGE_TX" \
  --arg challengeRuntimeCodeHash "$CHALLENGE_RUNTIME_CODE_HASH" \
  --arg challengePendingOwner "$CHALLENGE_PENDING_OWNER" \
  --arg challengeNextId "$CHALLENGE_NEXT_ID" \
  --arg challengeMinVersionReviewDelay "$CHALLENGE_MIN_VERSION_REVIEW_DELAY" \
  --arg computeVault "$COMPUTE_VAULT_ADDRESS" \
  --arg computeVaultTx "$COMPUTE_VAULT_TX" \
  --arg computeVaultRuntimeCodeHash "$COMPUTE_VAULT_RUNTIME_CODE_HASH" \
  --arg computeVaultOwner "$COMPUTE_VAULT_OWNER" \
  --arg computeVaultDeveloper "$COMPUTE_VAULT_DEVELOPER_READ" \
  --arg computeVaultMeteringVerifier "$COMPUTE_VAULT_METERING_VERIFIER_READ" \
  --arg computeVaultMeteringQvlVerifier "$COMPUTE_VAULT_METERING_QVL_VERIFIER_READ" \
  --arg computeVaultMeteringPolicySetHash "$COMPUTE_VAULT_METERING_POLICY_SET_HASH" \
  --arg computeVaultPendingMeteringVerifier "$COMPUTE_VAULT_PENDING_METERING_VERIFIER" \
  --arg computeVaultPendingMeteringQvlVerifier "$COMPUTE_VAULT_PENDING_METERING_QVL_VERIFIER" \
  --arg computeVaultPendingMeteringPolicySetHash "$COMPUTE_VAULT_PENDING_METERING_POLICY_SET_HASH" \
  --arg computeVaultPendingMeteringAt "$COMPUTE_VAULT_PENDING_METERING_AT" \
  --argjson computeVaultMeteringBindingFrozen "$COMPUTE_VAULT_METERING_BINDING_FROZEN" \
  --argjson computeVaultPaused "$COMPUTE_VAULT_PAUSED" \
  --arg computeVaultFeeBps "$COMPUTE_VAULT_FEE_BPS" \
  --argjson computeVaultFeeFrozen "$COMPUTE_VAULT_FEE_FROZEN" \
  --arg computeVaultAllowedAssetCount "$COMPUTE_VAULT_ALLOWED_ASSET_COUNT" \
  --arg computeVaultActiveRateCount "$COMPUTE_VAULT_ACTIVE_RATE_COUNT" \
  --arg computeVaultApprovedComposeCount "$COMPUTE_VAULT_APPROVED_COMPOSE_COUNT" \
  --arg computeVaultApprovedTeeCount "$COMPUTE_VAULT_APPROVED_TEE_COUNT" \
  --arg computeVaultPendingAssetCount "$COMPUTE_VAULT_PENDING_ASSET_COUNT" \
  --arg computeVaultPendingRateCount "$COMPUTE_VAULT_PENDING_RATE_COUNT" \
  --arg computeVaultPendingComposeCount "$COMPUTE_VAULT_PENDING_COMPOSE_COUNT" \
  --arg computeVaultPendingTeeCount "$COMPUTE_VAULT_PENDING_TEE_COUNT" \
  --argjson computeVaultComposePolicyFrozen "$COMPUTE_VAULT_COMPOSE_POLICY_FROZEN" \
  --argjson computeVaultTeeAdditionsFrozen "$COMPUTE_VAULT_TEE_ADDITIONS_FROZEN" \
  --argjson computeVaultRateAdditionsFrozen "$COMPUTE_VAULT_RATE_ADDITIONS_FROZEN" \
  --argjson computeVaultAssetAdditionsFrozen "$COMPUTE_VAULT_ASSET_ADDITIONS_FROZEN" \
  --arg emailOracle "$EMAIL_ORACLE_ADDRESS" \
  --arg emailOracleTx "$EMAIL_ORACLE_TX" \
  --arg emailOracleOwner "$EMAIL_ORACLE_OWNER" \
  --arg emailOraclePendingOwner "$EMAIL_ORACLE_PENDING_OWNER" \
  --argjson emailOracleProductionRelease "$EMAIL_ORACLE_PRODUCTION_RELEASE" \
  --arg emailOracleDelay "$EMAIL_ORACLE_DELAY" \
  --argjson emailOracleAllowAny "$EMAIL_ORACLE_ALLOW_ANY" \
  --argjson emailOracleCodeFrozen "$EMAIL_ORACLE_CODE_FROZEN" \
  --argjson emailOracleConsumersFrozen "$EMAIL_ORACLE_CONSUMERS_FROZEN" \
  --argjson emailOracleManagerAdditionsFrozen "$EMAIL_ORACLE_MANAGER_ADDITIONS_FROZEN" \
  --argjson emailOracleKmsFrozen "$EMAIL_ORACLE_KMS_FROZEN" \
  --arg emailOracleAllowedComposeCount "$EMAIL_ORACLE_ALLOWED_COMPOSE_COUNT" \
  --arg emailOraclePendingComposeCount "$EMAIL_ORACLE_PENDING_COMPOSE_COUNT" \
  --arg emailOracleAllowedDeviceCount "$EMAIL_ORACLE_ALLOWED_DEVICE_COUNT" \
  --arg emailOracleManagerCount "$EMAIL_ORACLE_MANAGER_COUNT" \
  --arg emailOracleConsumerComposeCount "$EMAIL_ORACLE_CONSUMER_COMPOSE_COUNT" \
  --arg emailOracleReleaseCompose "$EMAIL_ORACLE_RELEASE_COMPOSE" \
  --arg emailOracleReleaseDevice "$EMAIL_ORACLE_RELEASE_DEVICE" \
  --arg emailOracleReleaseManager "$EMAIL_ORACLE_RELEASE_MANAGER" \
  --arg emailOracleReleaseApp "$EMAIL_ORACLE_RELEASE_APP" \
  --arg emailOracleReleaseConsumerCompose "$EMAIL_ORACLE_RELEASE_CONSUMER_COMPOSE" \
  --arg emailOracleKmsContract "$EMAIL_ORACLE_KMS_CONTRACT" \
  --arg emailOracleKmsRuntimeHash "$EMAIL_ORACLE_KMS_RUNTIME_HASH" \
  --arg emailOracleKmsImplementation "$EMAIL_ORACLE_KMS_IMPLEMENTATION" \
  --arg emailOracleKmsImplementationRuntimeHash "$EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_HASH" \
  --arg emailOracleKmsRegistrationTx "$EMAIL_ORACLE_KMS_REGISTRATION_TX" \
  --arg emailOracleKmsRegistrationBlock "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK" \
  --arg emailOracleKmsRegistrationBlockHash "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH" \
  --arg emailOracleBootInfoHash "$EMAIL_ORACLE_BOOT_INFO_HASH" \
  --arg emailOracleRestartProofHash "$EMAIL_ORACLE_RESTART_PROOF_HASH" \
  --argjson emailOracleReleaseReady "$EMAIL_ORACLE_RELEASE_READY" \
  --arg emailOracleRuntimeCodeHash "$EMAIL_ORACLE_RUNTIME_CODE_HASH" \
  --arg executionPolicyAnchor "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  --arg executionPolicyAnchorTx "$EXECUTION_POLICY_ANCHOR_TX" \
  --arg executionPolicyAnchorRuntimeCodeHash "$EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH" \
  --arg executionPolicyAnchorDeploymentIntentSha256Bytes32 "$EXECUTION_POLICY_ANCHOR_DEPLOYMENT_INTENT_SHA256_BYTES32" \
  --arg executionPolicyAnchorReviewerGenesisAcceptanceSha256Bytes32 "$EXECUTION_POLICY_ANCHOR_REVIEWER_GENESIS_ACCEPTANCE_SHA256_BYTES32" \
  --arg executionPolicyAnchorAuthorityCommitmentReadProof "local_single_anvil_rpc_rehearsal_not_production_dual_rpc_evidence" \
  --arg executionPolicyAnchorAuthorityCommitmentReadBlock "$(jq -er '.executionPolicyAnchor.deploymentBlock | tostring' <<<"$DEPLOYMENT_RECEIPTS")" \
  --arg executionPolicyAnchorAuthorityCommitmentReadBlockHash "$(jq -er '.executionPolicyAnchor.deploymentBlockHash' <<<"$DEPLOYMENT_RECEIPTS")" \
  --arg executionPolicyAnchorOwner "$EXECUTION_POLICY_ANCHOR_OWNER" \
  --arg executionPolicyAnchorWriter "$EXECUTION_POLICY_ANCHOR_INITIAL_WRITER" \
  --arg executionPolicyAnchorWriterRelease "$EXECUTION_POLICY_ANCHOR_INITIAL_RELEASE" \
  --arg executionPolicyAnchorPendingWriter "$EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_WRITER" \
  --arg executionPolicyAnchorPendingRelease "$EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_RELEASE" \
  --arg executionPolicyAnchorPendingAt "$EXECUTION_POLICY_ANCHOR_INITIAL_PENDING_AT" \
  --argjson executionPolicyAnchorRotationsFrozen "$EXECUTION_POLICY_ANCHOR_INITIAL_ROTATIONS_FROZEN" \
  --argjson executionPolicyAnchorPaused "$EXECUTION_POLICY_ANCHOR_INITIAL_PAUSED" \
  --arg executionPolicyAnchorGlobalSequence "$EXECUTION_POLICY_ANCHOR_INITIAL_SEQUENCE" \
  --arg executionPolicyAnchorGlobalHead "$EXECUTION_POLICY_ANCHOR_INITIAL_HEAD" \
  --argjson verificationRequested false \
  -f "$MANIFEST_FILTER" > "$PRODUCTION_SHAPE_MANIFEST"

jq \
  --arg rpcUrl "$RPC_URL" \
  --arg clientVersion "$CLIENT_VERSION" \
  --arg helper "⚙️/tinker-delegate/contracts/scripts/rehearse-fresh-suite-anvil.sh" \
  --arg broadcastArtifact "$RUN_PATH" \
  --argjson sourceTreeClean "$SOURCE_TREE_CLEAN" \
  --arg tinkerProposeReleaseTx "$TINKER_PROPOSE_RELEASE_TX" \
  --arg tinkerActivateReleaseTx "$TINKER_ACTIVATE_RELEASE_TX" \
  --arg tinkerAuthorizeOneTx "$TINKER_AUTHORIZE_ONE_TX" \
  --arg tinkerAuthorizeTwoTx "$TINKER_AUTHORIZE_TWO_TX" \
  --arg tinkerSettleOneTx "$TINKER_SETTLE_ONE_TX" \
  --arg tinkerSettleTwoTx "$TINKER_SETTLE_TWO_TX" \
  --arg tinkerReleaseEligibleAt "$TINKER_RELEASE_ELIGIBLE_AT" \
  --arg tinkerReleaseManager "$TINKER_RELEASE_MANAGER" \
  --arg tinkerAccountCommitment "$TINKER_FINAL_ACCOUNT" \
  --arg tinkerMaxAddBalanceWei "$TINKER_FINAL_MAX_ADD" \
  --arg tinkerMaxSpendWei "$TINKER_FINAL_MAX_SPEND" \
  --arg tinkerComposeHash "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH" \
  --arg tinkerReleaseComposeRoot "$TINKER_RELEASE_COMPOSE_ROOT" \
  --arg tinkerReleaseManagerRoot "$TINKER_RELEASE_MANAGER_ROOT" \
  --arg tinkerReleaseCommitment "$TINKER_RELEASE_COMMITMENT" \
  --arg tinkerReleaseMaxAddBalanceWei "$TINKER_FINAL_RELEASE_MAX_ADD" \
  --arg tinkerReleaseMaxSpendWei "$TINKER_FINAL_RELEASE_MAX_SPEND" \
  --arg tinkerContractBalance "$TINKER_CONTRACT_BALANCE" \
  --arg diligenceProposeComposeTx "$DILIGENCE_PROPOSE_COMPOSE_TX" \
  --arg diligenceProposeEvaluatorPolicySetTx "$DILIGENCE_PROPOSE_EVALUATOR_POLICY_SET_TX" \
  --arg diligenceProposeResultVerifierTx "$DILIGENCE_PROPOSE_RESULT_VERIFIER_TX" \
  --arg diligenceProposeAttestationTx "$DILIGENCE_PROPOSE_ATTESTATION_TX" \
  --arg diligenceActivateComposeTx "$DILIGENCE_ACTIVATE_COMPOSE_TX" \
  --arg diligenceActivateEvaluatorPolicySetTx "$DILIGENCE_ACTIVATE_EVALUATOR_POLICY_SET_TX" \
  --arg diligenceFreezeEvaluatorPolicySetTx "$DILIGENCE_FREEZE_EVALUATOR_POLICY_SET_TX" \
  --arg diligenceActivateResultVerifierTx "$DILIGENCE_ACTIVATE_RESULT_VERIFIER_TX" \
  --arg diligenceFreezeResultVerifierTx "$DILIGENCE_FREEZE_RESULT_VERIFIER_TX" \
  --arg diligenceActivateAttestationTx "$DILIGENCE_ACTIVATE_ATTESTATION_TX" \
  --arg diligenceFreezeAttestationTx "$DILIGENCE_FREEZE_ATTESTATION_TX" \
  --arg diligenceProposeIdentityTx "$DILIGENCE_PROPOSE_IDENTITY_TX" \
  --arg diligenceActivateIdentityTx "$DILIGENCE_ACTIVATE_IDENTITY_TX" \
  --arg diligenceFreezeComposeTx "$DILIGENCE_FREEZE_COMPOSE_TX" \
  --arg diligenceFreezeIdentityTx "$DILIGENCE_FREEZE_IDENTITY_TX" \
  --arg diligenceCreateTx "$DILIGENCE_CREATE_TX" \
  --arg diligenceFundTx "$DILIGENCE_FUND_TX" \
  --arg diligenceSubmitTx "$DILIGENCE_SUBMIT_TX" \
  --arg diligenceAcceptTx "$DILIGENCE_ACCEPT_TX" \
  --arg diligenceResultVerifier "$DILIGENCE_FINAL_RESULT_VERIFIER" \
  --argjson diligenceResultVerifierFrozen "$DILIGENCE_FINAL_RESULT_VERIFIER_FROZEN" \
  --arg diligenceAttestationVerifier "$DILIGENCE_FINAL_ATTESTATION_VERIFIER" \
  --arg diligenceAttestationPolicyHash "$DILIGENCE_FINAL_ATTESTATION_POLICY_HASH" \
  --argjson diligenceAttestationBindingFrozen "$DILIGENCE_FINAL_ATTESTATION_FROZEN" \
  --arg diligenceEvaluatorPolicy1 "$DILIGENCE_EVALUATOR_POLICY_1" \
  --arg diligenceEvaluatorPolicy2 "$DILIGENCE_EVALUATOR_POLICY_2" \
  --arg diligenceEvaluatorPolicy3 "$DILIGENCE_EVALUATOR_POLICY_3" \
  --arg diligenceEvaluatorPolicySetRoot "$DILIGENCE_FINAL_EVALUATOR_POLICY_ROOT" \
  --arg diligenceApprovedEvaluatorPolicyCount "$DILIGENCE_FINAL_EVALUATOR_POLICY_COUNT" \
  --arg diligencePendingEvaluatorPolicyCount "$DILIGENCE_FINAL_PENDING_EVALUATOR_POLICY_COUNT" \
  --argjson diligenceEvaluatorPolicySetFrozen "$DILIGENCE_FINAL_EVALUATOR_POLICY_FROZEN" \
  --arg diligenceComposeHash "$DILIGENCE_COMPOSE_HASH" \
  --argjson diligenceComposeApproved "$DILIGENCE_FINAL_COMPOSE_APPROVED" \
  --arg diligenceApprovedComposeCount "$DILIGENCE_FINAL_APPROVED_COMPOSE_COUNT" \
  --arg diligencePendingComposeCount "$DILIGENCE_FINAL_PENDING_COMPOSE_COUNT" \
  --argjson diligenceComposeAdditionsFrozen "$DILIGENCE_FINAL_COMPOSE_ADDITIONS_FROZEN" \
  --arg diligenceTeeIdentity "$TEE_IDENTITY" \
  --arg diligenceTeeComposeHash "$DILIGENCE_FINAL_TEE_COMPOSE_HASH" \
  --arg diligenceApprovedTeeCount "$DILIGENCE_FINAL_APPROVED_TEE_COUNT" \
  --arg diligencePendingTeeCount "$DILIGENCE_FINAL_PENDING_TEE_COUNT" \
  --argjson diligenceTeeAdditionsFrozen "$DILIGENCE_FINAL_TEE_ADDITIONS_FROZEN" \
  --arg diligenceSelectedEvaluatorPolicy "$DEAL_EVALUATOR_POLICY" \
  --arg diligenceAttestationEvidenceHash "$DEAL_ATTESTATION_EVIDENCE_HASH" \
  --arg diligenceResultAuthorizationExpiry "$AUTHORIZATION_EXPIRY" \
  --arg diligenceAttestationAuthorizationExpiry "$ATTESTATION_AUTHORIZATION_EXPIRY" \
  --arg diligenceDealCount "$DEAL_COUNT" \
  --arg computeCost "$COMPUTE_COST" \
  --arg sellerPending "$SELLER_PENDING" \
  --arg developerPending "$DEVELOPER_PENDING" \
  --arg buyerPending "$BUYER_PENDING" \
  --arg challengeSetRegistrarTx "$CHALLENGE_SET_REGISTRAR_TX" \
  --arg challengeCreateTx "$CHALLENGE_CREATE_TX" \
  --arg challengeAddVersionTx "$CHALLENGE_ADD_VERSION_TX" \
  --arg challengePublishBlock "$CHALLENGE_PUBLISH_BLOCK" \
  --arg challengeReviewEligibleAt "$CHALLENGE_REVIEW_ELIGIBLE_AT" \
  --arg challengeFreezeBlock "$CHALLENGE_FREEZE_BLOCK" \
  --arg challengeFreezeTx "$CHALLENGE_FREEZE_TX" \
  --arg challengeOpenBlock "$CHALLENGE_OPEN_BLOCK" \
  --arg challengeOpenTx "$CHALLENGE_OPEN_TX" \
  --arg executionPolicyProposeWriterTx "$EXECUTION_POLICY_PROPOSE_WRITER_TX" \
  --arg executionPolicyActivateWriterTx "$EXECUTION_POLICY_ACTIVATE_WRITER_TX" \
  --arg executionPolicyFreezeWriterTx "$EXECUTION_POLICY_FREEZE_WRITER_TX" \
  --arg executionPolicyUnpauseTx "$EXECUTION_POLICY_UNPAUSE_TX" \
  --arg executionPolicyAnchorDecisionTx "$EXECUTION_POLICY_ANCHOR_DECISION_TX" \
  --arg executionPolicyWriter "$EXECUTION_POLICY_ANCHOR_WRITER" \
  --arg executionPolicyWriterRelease "$EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT" \
  --arg executionPolicyResourceHash "$EXECUTION_POLICY_RESOURCE_HASH" \
  --arg executionPolicyDecisionHash "$EXECUTION_POLICY_DECISION_HASH" \
  --arg executionPolicyGlobalHead "$EXECUTION_POLICY_FINAL_HEAD" \
  '
    .status = "local_ephemeral_rehearsal_complete"
    | .network = {
        name: "Local Anvil, Base Sepolia chain-id shape only",
        chainId: 84532,
        rpcEnv: "ANVIL_RPC_URL",
        rpcUrl: $rpcUrl,
        clientVersion: $clientVersion,
        explorerBaseUrl: null,
        localEphemeral: true
      }
    | .currentOperatorDeployer.keystoreAccount = null
    | .currentOperatorDeployer.signerMode = "anvil_unlocked_json_rpc"
    | .currentOperatorDeployer.fundingStatus = "local_prefunded"
    | .currentOperatorDeployer.privateKeyMaterial = "not_read_or_supplied"
    | .lastReviewedAt = .deploymentHistory[-1].deployedAt
    | .deploymentHistory[-1].kind = "local_ephemeral_fresh_suite_rehearsal"
    | .deploymentHistory[-1].localEphemeral = true
    | .deploymentHistory[-1].deploymentIntentSha256 = null
    | .deploymentHistory[-1].reviewerAuthorityGenesisAcceptanceSha256 = null
    | .deploymentHistory[-1].deploymentReviewEnvelopeSha256 = null
    | .deploymentHistory[-1].deploymentReviewEvidenceSha256 = null
    | .deploymentHistory[-1].authorityStage = "local_ephemeral_unreviewed_rehearsal"
    | .deploymentHistory[-1].deploymentReviewSemantics = "not_applicable_local_only"
    | .deploymentHistory[-1].cvmEvidenceStatus = "not_applicable_local_only"
    | .deploymentHistory[-1].verificationStatus = "not_applicable_local_only"
    | .freshDeployment.contractSuite.status = "local_ephemeral_rehearsal_complete"
    | .freshDeployment.contractSuite.helper = $helper
    | .freshDeployment.contractSuite.keystoreAccount = null
    | .freshDeployment.contractSuite.signerMode = "anvil_unlocked_json_rpc"
    | .freshDeployment.contractSuite.localEphemeral = true
    | .freshDeployment.contractSuite.deploymentIntentSha256 = null
    | .freshDeployment.contractSuite.reviewerAuthorityGenesisAcceptanceSha256 = null
    | .freshDeployment.contractSuite.deploymentReviewEnvelopeSha256 = null
    | .freshDeployment.contractSuite.deploymentReviewEvidenceSha256 = null
    | .freshDeployment.contractSuite.authorityStage = "local_ephemeral_unreviewed_rehearsal"
    | .freshDeployment.contractSuite.deploymentReviewSemantics = "not_applicable_local_only"
    | .freshDeployment.contractSuite.cvmEvidenceStatus = "not_applicable_local_only"
    | .freshDeployment.contractSuite.verificationStatus = "not_applicable_local_only"
    | .contracts |= with_entries(
        .value.baseScanUrl = null
        | .value.transactionUrl = null
        | .value.evidenceScope = "local_ephemeral_anvil_only"
        | .value.verificationStatus = "not_applicable_local_only"
      )
    | .contracts.tinkerAccountEncumbrance += {
        status: "deployed_exact_release_policy_frozen_active",
        pendingOwner: "0x0000000000000000000000000000000000000000",
        accountCommitment: $tinkerAccountCommitment,
        maxAddBalanceWei: $tinkerMaxAddBalanceWei,
        maxSpendWei: $tinkerMaxSpendWei,
        perOperationCaps: true,
        custodiesFunds: false,
        approvedComposeHashes: [$tinkerComposeHash],
        managers: [$tinkerReleaseManager],
        managerRoot: $tinkerReleaseManagerRoot,
        managerCount: 1,
        approvedComposeRoot: $tinkerReleaseComposeRoot,
        approvedComposeCount: 1,
        releasePolicyCommitment: $tinkerReleaseCommitment,
        releaseMaxAddBalanceWei: $tinkerReleaseMaxAddBalanceWei,
        releaseMaxSpendWei: $tinkerReleaseMaxSpendWei,
        releaseComposeHashes: [$tinkerComposeHash],
        releaseComposeRoot: $tinkerReleaseComposeRoot,
        releaseComposeCount: 1,
        releaseManagers: [$tinkerReleaseManager],
        releaseManagerRoot: $tinkerReleaseManagerRoot,
        releaseManagerCount: 1,
        pendingAccountCommitment: "0x0000000000000000000000000000000000000000000000000000000000000000",
        pendingMaxAddBalanceWei: "0",
        pendingMaxSpendWei: "0",
        pendingComposeHashes: [],
        pendingComposeRoot: "0x0000000000000000000000000000000000000000000000000000000000000000",
        pendingManagers: [],
        pendingManagerRoot: "0x0000000000000000000000000000000000000000000000000000000000000000",
        pendingReleasePolicyCommitment: "0x0000000000000000000000000000000000000000000000000000000000000000",
        pendingReleasePolicyActivatesAt: 0,
        pendingComposeCount: 0,
        pendingManagerCount: 0,
        releasePolicyFrozen: true,
        emergencyHalted: false,
        policyState: "exact_timelocked_release_policy_frozen_active"
      }
    | .contracts.diligenceRoom.rehearsalSnapshotStage = "post_deployment_pre_synthetic_lifecycle"
    | .rehearsalEvidence = {
        localEphemeral: true,
        externallyDeployed: false,
        chainIdShape: 84532,
        signerMode: "anvil_unlocked_json_rpc",
        rawSigningMaterialReadOrSupplied: false,
        sourceTreeClean: $sourceTreeClean,
        build: "forge_build_sizes_passed",
        contractTests: "full_forge_test_suite_passed",
        dryRun: "passed",
        broadcastArtifact: $broadcastArtifact,
        runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
        tinkerAccountEncumbrance: {
          releasePolicyCommitment: $tinkerReleaseCommitment,
          reviewEligibleAt: ($tinkerReleaseEligibleAt | tonumber),
          composeRoot: $tinkerReleaseComposeRoot,
          composeCount: 1,
          manager: $tinkerReleaseManager,
          managerRoot: $tinkerReleaseManagerRoot,
          managerCount: 1,
          releasePolicyFrozen: true,
          emergencyHalted: false,
          perOperationCaps: true,
          fullCapOperationsAuthorized: 2,
          custodialBalanceWei: ($tinkerContractBalance | tonumber),
          transactions: {
            proposeReleasePolicy: $tinkerProposeReleaseTx,
            activateAndFreezeReleasePolicy: $tinkerActivateReleaseTx,
            authorizeOperationOne: $tinkerAuthorizeOneTx,
            authorizeOperationTwo: $tinkerAuthorizeTwoTx,
            settleOperationOne: $tinkerSettleOneTx,
            settleOperationTwo: $tinkerSettleTwoTx
          }
        },
        diligenceLifecycle: {
          syntheticLocalOnly: true,
          finalState: "Accepted",
          boundedScoreBand: "Exceptional",
          dealCount: ($diligenceDealCount | tonumber),
          evaluatorPolicyCommitment: $diligenceSelectedEvaluatorPolicy,
          evaluatorPolicySetRoot: $diligenceEvaluatorPolicySetRoot,
          attestationEvidenceHash: $diligenceAttestationEvidenceHash,
          resultAuthorizationExpiry: ($diligenceResultAuthorizationExpiry | tonumber),
          attestationAuthorizationExpiry: ($diligenceAttestationAuthorizationExpiry | tonumber),
          computeCostWei: ($computeCost | tonumber),
          sellerPendingWei: ($sellerPending | tonumber),
          developerPendingWei: ($developerPending | tonumber),
          buyerPendingWei: ($buyerPending | tonumber),
          postDeploymentBindingState: {
            resultVerifier: $diligenceResultVerifier,
            resultVerifierFrozen: $diligenceResultVerifierFrozen,
            attestationVerifier: $diligenceAttestationVerifier,
            attestationReleasePolicyHash: $diligenceAttestationPolicyHash,
            attestationBindingFrozen: $diligenceAttestationBindingFrozen,
            evaluatorPolicyCommitments: [
              $diligenceEvaluatorPolicy1,
              $diligenceEvaluatorPolicy2,
              $diligenceEvaluatorPolicy3
            ],
            evaluatorPolicySetRoot: $diligenceEvaluatorPolicySetRoot,
            approvedEvaluatorPolicyCount: ($diligenceApprovedEvaluatorPolicyCount | tonumber),
            pendingEvaluatorPolicyCount: ($diligencePendingEvaluatorPolicyCount | tonumber),
            evaluatorPolicySetFrozen: $diligenceEvaluatorPolicySetFrozen,
            composeHash: $diligenceComposeHash,
            composeApproved: $diligenceComposeApproved,
            approvedComposeCount: ($diligenceApprovedComposeCount | tonumber),
            pendingComposeCount: ($diligencePendingComposeCount | tonumber),
            composeAdditionsFrozen: $diligenceComposeAdditionsFrozen,
            teeIdentity: $diligenceTeeIdentity,
            teeIdentityComposeHash: $diligenceTeeComposeHash,
            approvedTeeIdentityCount: ($diligenceApprovedTeeCount | tonumber),
            pendingTeeIdentityCount: ($diligencePendingTeeCount | tonumber),
            teeIdentityAdditionsFrozen: $diligenceTeeAdditionsFrozen
          },
          transactions: {
            proposeCompose: $diligenceProposeComposeTx,
            proposeEvaluatorPolicySet: $diligenceProposeEvaluatorPolicySetTx,
            proposeResultVerifier: $diligenceProposeResultVerifierTx,
            proposeAttestationBinding: $diligenceProposeAttestationTx,
            activateCompose: $diligenceActivateComposeTx,
            activateEvaluatorPolicySet: $diligenceActivateEvaluatorPolicySetTx,
            freezeEvaluatorPolicySet: $diligenceFreezeEvaluatorPolicySetTx,
            activateResultVerifier: $diligenceActivateResultVerifierTx,
            freezeResultVerifier: $diligenceFreezeResultVerifierTx,
            activateAttestationBinding: $diligenceActivateAttestationTx,
            freezeAttestationBinding: $diligenceFreezeAttestationTx,
            proposeTeeIdentity: $diligenceProposeIdentityTx,
            activateTeeIdentity: $diligenceActivateIdentityTx,
            freezeComposeAdditions: $diligenceFreezeComposeTx,
            freezeTeeIdentityAdditions: $diligenceFreezeIdentityTx,
            create: $diligenceCreateTx,
            fund: $diligenceFundTx,
            submitBoundedResult: $diligenceSubmitTx,
            accept: $diligenceAcceptTx
          }
        },
        challengeRegistry: {
          challengeId: 1,
          finalLifecycle: "Open",
          latestVersion: 2,
          configurationFrozen: true,
          custodialBalanceWei: 0,
          reviewDelaySeconds: 172800,
          phaseA: {
            action: "publish_version_2",
            publishBlock: ($challengePublishBlock | tonumber),
            reviewEligibleAt: ($challengeReviewEligibleAt | tonumber),
            publishTransaction: $challengeAddVersionTx
          },
          phaseB: {
            action: "freeze_then_open_after_review_delay",
            freezeBlock: ($challengeFreezeBlock | tonumber),
            openBlock: ($challengeOpenBlock | tonumber),
            freezeTransaction: $challengeFreezeTx,
            openTransaction: $challengeOpenTx
          },
          transactions: {
            setRegistrar: $challengeSetRegistrarTx,
            create: $challengeCreateTx,
            addVersion: $challengeAddVersionTx,
            freezeConfiguration: $challengeFreezeTx,
            open: $challengeOpenTx
          }
        },
        executionPolicyAnchor: {
          writer: $executionPolicyWriter,
          writerReleaseCommitment: $executionPolicyWriterRelease,
          writerRotationsFrozen: true,
          paused: false,
          globalSequence: 1,
          globalHead: $executionPolicyGlobalHead,
          resourceHash: $executionPolicyResourceHash,
          decisionHash: $executionPolicyDecisionHash,
          boundedOnChainPayload: "opaque_commitments_only",
          transactions: {
            proposeWriter: $executionPolicyProposeWriterTx,
            activateWriter: $executionPolicyActivateWriterTx,
            freezeWriterRotations: $executionPolicyFreezeWriterTx,
            unpause: $executionPolicyUnpauseTx,
            anchorDecision: $executionPolicyAnchorDecisionTx
          }
        }
      }
  ' "$PRODUCTION_SHAPE_MANIFEST" > "$EVIDENCE_MANIFEST"

jq -e \
  --arg operator "$DEPLOYMENT_OPERATOR" \
  --arg diligence "$DILIGENCE_ADDRESS" \
  --arg encumbrance "$ENCUMBRANCE_ADDRESS" \
  --arg royalty "$ROYALTY_ADDRESS" \
  --arg challenge "$CHALLENGE_ADDRESS" \
  --arg computeVault "$COMPUTE_VAULT_ADDRESS" \
  --arg emailOracle "$EMAIL_ORACLE_ADDRESS" \
  --arg executionPolicyAnchor "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  '
    .status == "local_ephemeral_rehearsal_complete"
    and .network.chainId == 84532
    and .network.localEphemeral == true
    and .currentOperatorDeployer.signerMode == "anvil_unlocked_json_rpc"
    and .currentOperatorDeployer.privateKeyMaterial == "not_read_or_supplied"
    and .freshDeployment.contractSuite.runtimeCodeProof == "exact_creation_reexecution_match_all_contracts"
    and .contracts.diligenceRoom.address == $diligence
    and .contracts.diligenceRoom.status == "deployed_fail_closed_pending_tee_binding"
    and .contracts.diligenceRoom.rehearsalSnapshotStage == "post_deployment_pre_synthetic_lifecycle"
    and .contracts.diligenceRoom.dealCount == 0
    and .contracts.diligenceRoom.resultVerifier == "0x0000000000000000000000000000000000000000"
    and .contracts.diligenceRoom.pendingResultVerifier == "0x0000000000000000000000000000000000000000"
    and .contracts.diligenceRoom.pendingResultVerifierActivatesAt == 0
    and .contracts.diligenceRoom.resultVerifierFrozen == false
    and .contracts.diligenceRoom.attestationVerifier == "0x0000000000000000000000000000000000000000"
    and .contracts.diligenceRoom.attestationBindingFrozen == false
    and .contracts.diligenceRoom.evaluatorPolicyCommitments == []
    and .contracts.diligenceRoom.approvedEvaluatorPolicyCount == 0
    and .contracts.diligenceRoom.pendingEvaluatorPolicyCount == 0
    and .contracts.diligenceRoom.evaluatorPolicySetFrozen == false
    and .contracts.diligenceRoom.pendingEvaluatorPolicyProposals == []
    and .contracts.diligenceRoom.approvedComposeCount == 0
    and .contracts.diligenceRoom.approvedTeeIdentityCount == 0
    and .contracts.diligenceRoom.policyState == "fail_closed_pending_cvm_binding"
    and .contracts.tinkerAccountEncumbrance.address == $encumbrance
    and .contracts.tinkerAccountEncumbrance.status == "deployed_exact_release_policy_frozen_active"
    and .contracts.tinkerAccountEncumbrance.pendingOwner == "0x0000000000000000000000000000000000000000"
    and .contracts.tinkerAccountEncumbrance.maxAddBalanceWei == "5000000000000000000"
    and (.contracts.tinkerAccountEncumbrance.maxAddBalanceWei | type) == "string"
    and .contracts.tinkerAccountEncumbrance.maxSpendWei == "2000000000000000000"
    and (.contracts.tinkerAccountEncumbrance.maxSpendWei | type) == "string"
    and .contracts.tinkerAccountEncumbrance.releasePolicyFrozen == true
    and .contracts.tinkerAccountEncumbrance.emergencyHalted == false
    and .contracts.tinkerAccountEncumbrance.approvedComposeCount == 1
    and .contracts.tinkerAccountEncumbrance.managerCount == 1
    and (.contracts.tinkerAccountEncumbrance.approvedComposeHashes | length) == 1
    and (.contracts.tinkerAccountEncumbrance.managers | length) == 1
    and (.contracts.tinkerAccountEncumbrance.releasePolicyCommitment | test("^0x[0-9a-fA-F]{64}$"))
    and .contracts.tinkerAccountEncumbrance.releasePolicyCommitment != "0x0000000000000000000000000000000000000000000000000000000000000000"
    and .contracts.tinkerAccountEncumbrance.releaseMaxAddBalanceWei == "5000000000000000000"
    and .contracts.tinkerAccountEncumbrance.releaseMaxSpendWei == "2000000000000000000"
    and (.contracts.tinkerAccountEncumbrance.releaseComposeHashes | length) == 1
    and .contracts.tinkerAccountEncumbrance.releaseComposeRoot == .contracts.tinkerAccountEncumbrance.approvedComposeRoot
    and .contracts.tinkerAccountEncumbrance.releaseComposeCount == 1
    and (.contracts.tinkerAccountEncumbrance.releaseManagers | length) == 1
    and .contracts.tinkerAccountEncumbrance.releaseManagerRoot == .contracts.tinkerAccountEncumbrance.managerRoot
    and .contracts.tinkerAccountEncumbrance.releaseManagerCount == 1
    and .contracts.tinkerAccountEncumbrance.pendingAccountCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
    and .contracts.tinkerAccountEncumbrance.pendingMaxAddBalanceWei == "0"
    and .contracts.tinkerAccountEncumbrance.pendingMaxSpendWei == "0"
    and .contracts.tinkerAccountEncumbrance.pendingComposeHashes == []
    and .contracts.tinkerAccountEncumbrance.pendingComposeRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
    and .contracts.tinkerAccountEncumbrance.pendingComposeCount == 0
    and .contracts.tinkerAccountEncumbrance.pendingManagers == []
    and .contracts.tinkerAccountEncumbrance.pendingManagerRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
    and .contracts.tinkerAccountEncumbrance.pendingManagerCount == 0
    and .contracts.tinkerAccountEncumbrance.pendingReleasePolicyCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
    and .contracts.tinkerAccountEncumbrance.pendingReleasePolicyActivatesAt == 0
    and .contracts.tinkerAccountEncumbrance.policyState == "exact_timelocked_release_policy_frozen_active"
    and .contracts.tinkerAccountEncumbrance.perOperationCaps == true
    and .contracts.tinkerAccountEncumbrance.custodiesFunds == false
    and .contracts.royaltyDistributor.address == $royalty
    and .contracts.challengeRegistry.address == $challenge
    and .contracts.computeCreditVault.address == $computeVault
    and .contracts.computeCreditVault.policyState == "execution_fail_closed_pending_timelocked_release_binding"
    and .contracts.computeCreditVault.approvedComposeCount == 0
    and .contracts.computeCreditVault.developerFeeFrozen == true
    and .contracts.emailOracleAuth.address == $emailOracle
    and .contracts.executionPolicyAnchor.address == $executionPolicyAnchor
    and .contracts.executionPolicyAnchor.policyState == "anchoring_fail_closed_pending_timelocked_release_writer"
    and .contracts.executionPolicyAnchor.paused == true
    and .contracts.executionPolicyAnchor.globalSequence == 0
    and ([.contracts[] | .runtimeCodeHash | test("^0x[0-9a-fA-F]{64}$")] | all)
    and ([.contracts[] | .deploymentTx | test("^0x[0-9a-fA-F]{64}$")] | all)
    and ([.contracts[] | .deploymentTxFrom == $operator] | all)
    and ([.contracts[] | .deploymentReceiptStatus == "success"] | all)
    and ([.contracts[] | .deploymentReceiptContractAddress == .address] | all)
    and ([.contracts[] | (.deploymentBlock | type) == "number" and .deploymentBlock > 0] | all)
    and ([.contracts[] | .deploymentBlockHash | test("^0x[0-9a-f]{64}$") and . != "0x" + ("0" * 64)] | all)
    and ([.deploymentHistory[-1].deployedContracts[] | .deploymentTxFrom == $operator] | all)
    and ([.deploymentHistory[-1].deployedContracts[] | .deploymentReceiptStatus == "success"] | all)
    and ([.deploymentHistory[-1].deployedContracts[] | .deploymentReceiptContractAddress == .address] | all)
    and ([.deploymentHistory[-1].deployedContracts[] | (.deploymentBlock | type) == "number" and .deploymentBlock > 0] | all)
    and ([.deploymentHistory[-1].deployedContracts[] | .deploymentBlockHash | test("^0x[0-9a-f]{64}$") and . != "0x" + ("0" * 64)] | all)
    and ([.contracts[] | .evidenceScope == "local_ephemeral_anvil_only"] | all)
    and .rehearsalEvidence.externallyDeployed == false
    and .rehearsalEvidence.rawSigningMaterialReadOrSupplied == false
    and .rehearsalEvidence.tinkerAccountEncumbrance.releasePolicyFrozen == true
    and .rehearsalEvidence.tinkerAccountEncumbrance.emergencyHalted == false
    and .rehearsalEvidence.tinkerAccountEncumbrance.fullCapOperationsAuthorized == 2
    and .rehearsalEvidence.tinkerAccountEncumbrance.perOperationCaps == true
    and .rehearsalEvidence.tinkerAccountEncumbrance.custodialBalanceWei == 0
    and .rehearsalEvidence.diligenceLifecycle.syntheticLocalOnly == true
    and .rehearsalEvidence.diligenceLifecycle.finalState == "Accepted"
    and .rehearsalEvidence.diligenceLifecycle.dealCount == 1
    and .rehearsalEvidence.diligenceLifecycle.evaluatorPolicyCommitment == .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.evaluatorPolicyCommitments[0]
    and .rehearsalEvidence.diligenceLifecycle.evaluatorPolicySetRoot == .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.evaluatorPolicySetRoot
    and (.rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.evaluatorPolicyCommitments | length) == 3
    and ([.rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.evaluatorPolicyCommitments[] | test("^0x[0-9a-fA-F]{64}$") and . != "0x" + ("0" * 64)] | all)
    and (.rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.evaluatorPolicyCommitments | unique | length) == 3
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.approvedEvaluatorPolicyCount == 3
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.pendingEvaluatorPolicyCount == 0
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.evaluatorPolicySetFrozen == true
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.resultVerifier != "0x0000000000000000000000000000000000000000"
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.resultVerifierFrozen == true
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.attestationVerifier != "0x0000000000000000000000000000000000000000"
    and (.rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.attestationReleasePolicyHash | test("^0x[0-9a-fA-F]{64}$"))
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.attestationBindingFrozen == true
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.composeApproved == true
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.approvedComposeCount == 1
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.pendingComposeCount == 0
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.composeAdditionsFrozen == true
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.teeIdentityComposeHash == .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.composeHash
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.approvedTeeIdentityCount == 1
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.pendingTeeIdentityCount == 0
    and .rehearsalEvidence.diligenceLifecycle.postDeploymentBindingState.teeIdentityAdditionsFrozen == true
    and (.rehearsalEvidence.diligenceLifecycle.attestationEvidenceHash | test("^0x[0-9a-fA-F]{64}$"))
    and .rehearsalEvidence.diligenceLifecycle.attestationEvidenceHash != "0x" + ("0" * 64)
    and .rehearsalEvidence.diligenceLifecycle.resultAuthorizationExpiry == .rehearsalEvidence.diligenceLifecycle.attestationAuthorizationExpiry
    and .rehearsalEvidence.challengeRegistry.finalLifecycle == "Open"
    and .rehearsalEvidence.challengeRegistry.latestVersion == 2
    and .rehearsalEvidence.challengeRegistry.configurationFrozen == true
    and .rehearsalEvidence.challengeRegistry.reviewDelaySeconds == 172800
    and .rehearsalEvidence.challengeRegistry.phaseB.freezeBlock > .rehearsalEvidence.challengeRegistry.phaseA.publishBlock
    and .rehearsalEvidence.challengeRegistry.phaseB.openBlock >= .rehearsalEvidence.challengeRegistry.phaseB.freezeBlock
    and .rehearsalEvidence.executionPolicyAnchor.globalSequence == 1
    and .rehearsalEvidence.executionPolicyAnchor.writerRotationsFrozen == true
    and .rehearsalEvidence.executionPolicyAnchor.paused == false
  ' "$EVIDENCE_MANIFEST" >/dev/null

# Retain only the reviewable broadcast, receipts, and explicitly local manifest.
# Foundry's compiler cache and the unlabelled intermediate manifest are not
# evidence and should not outlive the rehearsal.
rm -f "$PRODUCTION_SHAPE_MANIFEST"
rm -rf "$FOUNDRY_CACHE_PATH" "$FOUNDRY_OUT"

echo
echo "Local ephemeral fresh-suite rehearsal passed."
echo "DiligenceRoom:             $DILIGENCE_ADDRESS ($DILIGENCE_TX)"
echo "TinkerAccountEncumbrance:  $ENCUMBRANCE_ADDRESS ($ENCUMBRANCE_TX)"
echo "RoyaltyDistributor:        $ROYALTY_ADDRESS ($ROYALTY_TX)"
echo "ChallengeRegistry:         $CHALLENGE_ADDRESS ($CHALLENGE_TX)"
echo "ComputeCreditVault:        $COMPUTE_VAULT_ADDRESS ($COMPUTE_VAULT_TX)"
echo "EmailOracleAuth:           $EMAIL_ORACLE_ADDRESS ($EMAIL_ORACLE_TX)"
echo "ExecutionPolicyAnchor:     $EXECUTION_POLICY_ANCHOR_ADDRESS ($EXECUTION_POLICY_ANCHOR_TX)"
echo "Tinker release:            exact policy frozen after review at $TINKER_RELEASE_ELIGIBLE_AT, tx $TINKER_ACTIVATE_RELEASE_TX"
echo "Diligence lifecycle:       Accepted, tx $DILIGENCE_ACCEPT_TX"
echo "Challenge behavior:        Phase A version 2 at block $CHALLENGE_PUBLISH_BLOCK; Phase B frozen/open after review, tx $CHALLENGE_OPEN_TX"
echo "Policy anchor behavior:    writer frozen, sequence 1, tx $EXECUTION_POLICY_ANCHOR_DECISION_TX"
echo "Evidence manifest:         $EVIDENCE_MANIFEST"
echo "All addresses and transactions above are local, ephemeral Anvil evidence only."
