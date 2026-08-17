#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
CHAIN_ID=84532
ACCOUNT=dev
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
EIP1967_IMPLEMENTATION_SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-email-oracle-release-manifest.jq"
RUN_PATH="$CONTRACTS_DIR/broadcast/ConfigureEmailOracleRelease.s.sol/$CHAIN_ID/run-latest.json"
LEDGER_TEMP_PATH=""
ACTION_RECEIPTS_PATH=""
AUTHORITY_REVIEW_RECEIPT_PATH=""
AUTHORITY_REVIEW_RECEIPT_DIR=""

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

cleanup_email_release_evidence() {
  if [ -n "${LEDGER_TEMP_PATH:-}" ]; then
    rm -f -- "$LEDGER_TEMP_PATH"
    LEDGER_TEMP_PATH=""
  fi
  if [ -n "${ACTION_RECEIPTS_PATH:-}" ]; then
    rm -f -- "$ACTION_RECEIPTS_PATH"
    ACTION_RECEIPTS_PATH=""
  fi
  if [ -n "${AUTHORITY_REVIEW_RECEIPT_DIR:-}" ]; then
    rm -rf -- "$AUTHORITY_REVIEW_RECEIPT_DIR"
    AUTHORITY_REVIEW_RECEIPT_DIR=""
    AUTHORITY_REVIEW_RECEIPT_PATH=""
  fi
}

trap 'cleanup_email_release_evidence; cleanup_operator_policy_projection' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; email release identity/evidence is never inferred." >&2
    exit 1
  fi
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

validate_address() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]] || [ "$(lower "$value")" = "$ZERO_ADDRESS" ]; then
    echo "$name must be a nonzero Ethereum address." >&2
    exit 1
  fi
}

validate_bytes32() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] || [ "$(lower "$value")" = "$ZERO_BYTES32" ]; then
    echo "$name must be a nonzero bytes32 value." >&2
    exit 1
  fi
}

validate_bool() {
  local name="$1" value="$2"
  if [ "$value" != "true" ] && [ "$value" != "false" ]; then
    echo "$name must be true or false." >&2
    exit 1
  fi
}

validate_sha256() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [[ "$value" =~ ^sha256:0{64}$ ]]; then
    echo "$name must be a nonzero lowercase sha256:<64-hex> digest." >&2
    exit 1
  fi
}

file_mode() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"
}

deployment_ledger_sha256() {
  printf 'sha256:%s' "$(shasum -a 256 "$MANIFEST_PATH" | awk '{print $1}')"
}

validate_review_envelope_file() {
  require_env FINAL_RELEASE_AUTHORITY_CORE_PATH
  require_env OPERATOR_POLICY_REVIEW_ENVELOPE_PATH
  if [[ "$FINAL_RELEASE_AUTHORITY_CORE_PATH" != /* ]] \
    || [ ! -f "$FINAL_RELEASE_AUTHORITY_CORE_PATH" ] \
    || [ -L "$FINAL_RELEASE_AUTHORITY_CORE_PATH" ] \
    || [ ! -r "$FINAL_RELEASE_AUTHORITY_CORE_PATH" ]; then
    echo "FINAL_RELEASE_AUTHORITY_CORE_PATH must be an absolute, readable, non-symlink regular JSON file." >&2
    exit 1
  fi
  if [[ "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" != /* ]] \
    || [ ! -f "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" ] \
    || [ -L "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" ] \
    || [ ! -r "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" ]; then
    echo "OPERATOR_POLICY_REVIEW_ENVELOPE_PATH must be an absolute, readable, non-symlink regular JSON file." >&2
    exit 1
  fi
  local authority_size envelope_size envelope_sha
  authority_size="$(wc -c < "$FINAL_RELEASE_AUTHORITY_CORE_PATH" | tr -d '[:space:]')"
  if [[ ! "$authority_size" =~ ^[1-9][0-9]*$ ]] || [ "$authority_size" -gt 65536 ]; then
    echo "Final release authority core must be between 1 byte and 64 KiB." >&2
    exit 1
  fi
  envelope_size="$(wc -c < "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" | tr -d '[:space:]')"
  if [[ ! "$envelope_size" =~ ^[1-9][0-9]*$ ]] || [ "$envelope_size" -gt 65536 ]; then
    echo "Operator-policy review envelope must be between 1 byte and 64 KiB." >&2
    exit 1
  fi
  envelope_sha="sha256:$(shasum -a 256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" | awk '{print $1}')"
  if [ "$envelope_sha" != "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" ]; then
    echo "Operator-policy review envelope file does not match OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256." >&2
    exit 1
  fi
}

validate_authority_review_envelope() {
  AUTHORITY_REVIEW_RECEIPT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dnai-email-authority-review.XXXXXX")"
  chmod 700 "$AUTHORITY_REVIEW_RECEIPT_DIR"
  AUTHORITY_REVIEW_RECEIPT_PATH="$AUTHORITY_REVIEW_RECEIPT_DIR/receipt.json"
  if ! node "$ROOT_DIR/scripts/operator-policy-packet.mjs" \
    check-review \
    --in "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" \
    --subject "$FINAL_RELEASE_AUTHORITY_CORE_PATH" \
    --receipt-out "$AUTHORITY_REVIEW_RECEIPT_PATH" \
    >/dev/null; then
    echo "Final-authority review-envelope validation failed; Email release remains fail closed." >&2
    exit 1
  fi
  if [ ! -f "$AUTHORITY_REVIEW_RECEIPT_PATH" ] || [ -L "$AUTHORITY_REVIEW_RECEIPT_PATH" ]; then
    echo "Final-authority review validator did not create a safe receipt." >&2
    exit 1
  fi
  chmod 600 "$AUTHORITY_REVIEW_RECEIPT_PATH"
  # The exact success receipt is checked below. This is deliberately separate
  # from the pre-broadcast deployment-intent evidence boundary.
  if ! jq -e \
    --arg subjectSha "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --arg envelopeSha "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" '
      keys == [
        "actionScopeCount",
        "checkpoint",
        "reviewEnvelopeSha256",
        "reviewEvidenceSha256",
        "reviewerDeclarationCount",
        "schema",
        "status",
        "subjectKind",
        "subjectSemanticValidation",
        "subjectSha256",
        "truthStatus"
      ] and
      .schema == "dnai.authority-review-envelope-validation-receipt.v1" and
      .status == "valid" and
      .truthStatus == "canonical_subject_binding_and_review_declarations_validated_not_signatures_key_control_deployment_or_tdx" and
      .subjectKind == "final_release_authority" and
      .subjectSha256 == $subjectSha and
      .reviewEnvelopeSha256 == $envelopeSha and
      (.reviewEvidenceSha256 | type == "string" and test("^sha256:[0-9a-f]{64}$") and . != ("sha256:" + ("0" * 64))) and
      .checkpoint == "after_measured_cvms_before_any_release_ceremony_transaction" and
      .actionScopeCount == 6 and
      .reviewerDeclarationCount == 2 and
      .subjectSemanticValidation == "final_release_authority_validated"
    ' "$AUTHORITY_REVIEW_RECEIPT_PATH" >/dev/null; then
    echo "Final-authority review validator returned an unexpected or mismatched receipt." >&2
    exit 1
  fi
}

validate_deployment_ledger() {
  if [[ "$MANIFEST_PATH" != /* ]] \
    || [ ! -f "$MANIFEST_PATH" ] \
    || [ -L "$MANIFEST_PATH" ] \
    || [ ! -r "$MANIFEST_PATH" ] \
    || [ ! -w "$MANIFEST_PATH" ] \
    || [ ! -w "$(dirname "$MANIFEST_PATH")" ]; then
    echo "DEPLOYMENT_MANIFEST_PATH must be an absolute, writable, non-symlink regular JSON file in a writable directory." >&2
    exit 1
  fi
  if [ ! -f "$MANIFEST_FILTER" ] || [ -L "$MANIFEST_FILTER" ]; then
    echo "Email release ledger merge filter is missing or unsafe." >&2
    exit 1
  fi
  local ledger_size
  ledger_size="$(wc -c < "$MANIFEST_PATH" | tr -d '[:space:]')"
  if [[ ! "$ledger_size" =~ ^[0-9]+$ ]] || [ "$ledger_size" -gt 8388608 ]; then
    echo "Deployment ledger exceeds the bounded 8 MiB release limit." >&2
    exit 1
  fi
  if ! jq -e \
    --arg address "$(lower "$EMAIL_ORACLE_AUTH_ADDRESS")" \
    --arg runtime "$(lower "$EMAIL_ORACLE_RUNTIME_CODE_HASH")" \
    --arg source "$RELEASE_SHA" '
      .network.chainId == 84532 and
      (.contracts.emailOracleAuth | type) == "object" and
      ((.contracts.emailOracleAuth.address // "") | ascii_downcase) == $address and
      ((.contracts.emailOracleAuth.runtimeCodeHash // "") | ascii_downcase) == $runtime and
      .contracts.emailOracleAuth.sourceCommit == $source and
      ((.emailOracleReleaseHistory // []) | type) == "array"
    ' "$MANIFEST_PATH" >/dev/null; then
    echo "Deployment ledger EmailOracleAuth address/runtime/source does not match this exact release." >&2
    exit 1
  fi
}

validate_deployment_ledger_phase_history() {
  local expected_prior
  expected_prior="$(expected_prior_release_actions)"
  if ! jq -e \
    --arg address "$(lower "$EMAIL_ORACLE_AUTH_ADDRESS")" \
    --arg runtime "$(lower "$EMAIL_ORACLE_RUNTIME_CODE_HASH")" \
    --arg source "$RELEASE_SHA" \
    --arg finalAuthority "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --argjson expected "$expected_prior" '
      [(.emailOracleReleaseHistory // [])[]
        | select(
            type == "object" and
            .kind == "email_oracle_exact_release_action" and
            (.emailOracleAuthAddress | type) == "string" and
            (.emailOracleAuthAddress | ascii_downcase) == $address and
            .sourceCommit == $source
          )
      ] as $prior |
      [$prior[] | {phase, actionIndex, action}] == $expected and
      ($prior | all(
        keys == [
          "action",
          "actionIndex",
          "blockHash",
          "blockNumber",
          "blockTimestamp",
          "chainId",
          "emailOracleAuthAddress",
          "finalAuthoritySha256",
          "kind",
          "phase",
          "postState",
          "recordedAt",
          "reviewEnvelopeSha256",
          "runtimeCodeHash",
          "sourceCommit",
          "transactionHash"
        ] and
        .chainId == 84532 and
        ((.runtimeCodeHash // "") | ascii_downcase) == $runtime and
        .finalAuthoritySha256 == $finalAuthority and
        (.reviewEnvelopeSha256 | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
        (.transactionHash | type == "string" and test("^0x[0-9a-f]{64}$")) and
        (.blockHash | type == "string" and test("^0x[0-9a-f]{64}$")) and
        (.blockNumber | type == "number" and . > 0 and . == floor) and
        (.blockTimestamp | type == "number" and . > 0 and . == floor) and
        (.recordedAt | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
        (.postState | type) == "object"
      )) and
      ([$prior[].transactionHash] | unique | length) == ($prior | length)
    ' "$MANIFEST_PATH" >/dev/null; then
    echo "Deployment ledger is missing the exact ordered evidence required before this Email release phase." >&2
    exit 1
  fi
}

read_value() {
  cast call "$EMAIL_ORACLE_AUTH_ADDRESS" "$1" "${@:2}" --rpc-url "$BASE_SEPOLIA_RPC_URL"
}

read_uint() {
  read_value "$@" | awk '{print $1}'
}

require_exact_state() {
  local label="$1" actual="$2" expected="$3"
  if [ "$(lower "$actual")" != "$(lower "$expected")" ]; then
    echo "Post-broadcast Email release state mismatch for $label." >&2
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
    echo "Refusing email governance broadcast from a dirty source tree." >&2
    exit 1
  fi
}

read_rpc_object() {
  jq -c 'if type == "object" and has("result") then .result else . end'
}

require_exact_external_evidence() {
  require_env RELEASE_SHA
  require_env EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH
  if [[ "$EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH" != /* ]] \
    || [ ! -f "$EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH" ] \
    || [ -L "$EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH" ]; then
    echo "EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH must be an absolute, non-symlink regular JSON file." >&2
    exit 1
  fi

  local evidence_sha canonical_sha
  evidence_sha="0x$(shasum -a 256 "$EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH" | awk '{print $1}')"
  if [ "$(lower "$evidence_sha")" != "$(lower "$EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256")" ]; then
    echo "External evidence SHA-256 does not match EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256." >&2
    exit 1
  fi
  canonical_sha="0x$(jq -S -c . "$EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH" | shasum -a 256 | awk '{print $1}')"
  if [ "$(lower "$canonical_sha")" != "$(lower "$evidence_sha")" ]; then
    echo "External Email/KMS/restart evidence must be exact sorted compact canonical JSON with one trailing newline." >&2
    exit 1
  fi

  jq -e \
    --arg release "$RELEASE_SHA" \
    --arg auth "$(lower "$EMAIL_ORACLE_AUTH_ADDRESS")" \
    --arg compose "$(lower "$EMAIL_ORACLE_COMPOSE_HASH")" \
    --arg device "$(lower "$EMAIL_ORACLE_DEVICE_ID")" \
    --arg consumer "$(lower "$EMAIL_ORACLE_CONSUMER_APP_ID")" \
    --arg kms "$(lower "$EMAIL_ORACLE_KMS_ADDRESS")" \
    --arg kmsCode "$(lower "$EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH")" \
    --arg implementation "$(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS")" \
    --arg implementationCode "$(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH")" \
    --arg tx "$(lower "$EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH")" \
    --argjson block "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK" \
    --arg blockHash "$(lower "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH")" \
    --arg instance "$(lower "$EMAIL_ORACLE_BOOT_INSTANCE_ID")" \
    --arg mrAggregated "$(lower "$EMAIL_ORACLE_BOOT_MR_AGGREGATED")" \
    --arg mrSystem "$(lower "$EMAIL_ORACLE_BOOT_MR_SYSTEM")" \
    --arg osImage "$(lower "$EMAIL_ORACLE_BOOT_OS_IMAGE_HASH")" '
      keys == ["chain_id","email_oracle_auth","kms","main_cvm","qvl_verification","registration","release_sha","restart_key_derivation","schema","status","target_boot"] and
      .schema == "dnai.email-oracle-external-release-evidence.v1" and
      .status == "external_evidence_verified" and
      .chain_id == 84532 and .release_sha == $release and
      (.email_oracle_auth | ascii_downcase) == $auth and
      (.main_cvm | keys) == ["compose_hash","consumer_app_id","cvm_id","device_id"] and
      (.main_cvm.cvm_id | type == "string" and length > 0 and length <= 160) and
      (.main_cvm.compose_hash | ascii_downcase) == $compose and
      (.main_cvm.device_id | ascii_downcase) == $device and
      (.main_cvm.consumer_app_id | ascii_downcase) == $consumer and
      (.kms | keys) == ["contract_address","implementation_address","implementation_runtime_code_hash","runtime_code_hash","source_commit","source_repository","verification_status","verification_url"] and
      (.kms.contract_address | ascii_downcase) == $kms and
      (.kms.runtime_code_hash | ascii_downcase) == $kmsCode and
      (.kms.implementation_address | ascii_downcase) == $implementation and
      (.kms.implementation_runtime_code_hash | ascii_downcase) == $implementationCode and
      .kms.source_repository == "https://github.com/Dstack-TEE/dstack" and
      (.kms.source_commit | test("^[0-9a-f]{40}$")) and
      .kms.verification_status == "verified_source_and_runtime" and
      (.kms.verification_url | test("^https://")) and
      (.registration | keys) == ["block_hash","block_number","registered_apps_readback","transaction_hash"] and
      (.registration.transaction_hash | ascii_downcase) == $tx and
      .registration.block_number == $block and
      (.registration.block_hash | ascii_downcase) == $blockHash and
      .registration.registered_apps_readback == true and
      (.target_boot | keys) == ["advisory_ids","instance_id","kms_is_app_allowed","mr_aggregated","mr_system","os_image_hash","tcb_status"] and
      (.target_boot.instance_id | ascii_downcase) == $instance and
      (.target_boot.mr_aggregated | ascii_downcase) == $mrAggregated and
      (.target_boot.mr_system | ascii_downcase) == $mrSystem and
      (.target_boot.os_image_hash | ascii_downcase) == $osImage and
      .target_boot.tcb_status == "UpToDate" and .target_boot.advisory_ids == [] and
      .target_boot.kms_is_app_allowed == true and
      (.restart_key_derivation | keys) == ["derive_key_succeeded_after","derive_key_succeeded_before","key_path","post_restart_commitment","pre_restart_commitment","raw_key_egress","raw_secret_egress","restart_observed","status"] and
      .restart_key_derivation.status == "verified_after_real_cvm_restart" and
      .restart_key_derivation.key_path == "email/creds" and
      .restart_key_derivation.restart_observed == true and
      .restart_key_derivation.derive_key_succeeded_before == true and
      .restart_key_derivation.derive_key_succeeded_after == true and
      .restart_key_derivation.raw_key_egress == false and
      .restart_key_derivation.raw_secret_egress == false and
      (.restart_key_derivation.pre_restart_commitment | test("^0x[0-9a-f]{64}$")) and
      .restart_key_derivation.pre_restart_commitment != "0x" + ("0" * 64) and
      .restart_key_derivation.post_restart_commitment == .restart_key_derivation.pre_restart_commitment and
      (.qvl_verification | keys) == ["status","verdict_sha256","verdict_url"] and
      .qvl_verification.status == "verified" and
      (.qvl_verification.verdict_sha256 | test("^0x[0-9a-f]{64}$")) and
      (.qvl_verification.verdict_url | test("^https://"))
    ' "$EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH" >/dev/null || {
      echo "External Email/KMS/restart evidence is missing, noncanonical, or does not match the release inputs." >&2
      exit 1
    }
}

verify_live_kms_registration() {
  local receipt transaction block expected_input event_topic expected_data stored_implementation
  receipt="$(cast rpc --rpc-url "$BASE_SEPOLIA_RPC_URL" eth_getTransactionReceipt "$EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH" | read_rpc_object)"
  transaction="$(cast rpc --rpc-url "$BASE_SEPOLIA_RPC_URL" eth_getTransactionByHash "$EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH" | read_rpc_object)"
  block="$(cast rpc --rpc-url "$BASE_SEPOLIA_RPC_URL" eth_getBlockByNumber "$(cast to-hex "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK")" false | read_rpc_object)"
  expected_input="$(cast calldata 'registerApp(address)' "$EMAIL_ORACLE_AUTH_ADDRESS")"
  event_topic="$(cast keccak 'AppRegistered(address)')"
  expected_data="$(cast abi-encode 'f(address)' "$EMAIL_ORACLE_AUTH_ADDRESS")"

  jq -e \
    --arg tx "$(lower "$EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH")" \
    --arg kms "$(lower "$EMAIL_ORACLE_KMS_ADDRESS")" \
    --arg blockHash "$(lower "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH")" \
    --arg topic "$(lower "$event_topic")" \
    --arg data "$(lower "$expected_data")" '
      . != null and (.transactionHash | ascii_downcase) == $tx and .status == "0x1" and
      (.to | ascii_downcase) == $kms and (.blockHash | ascii_downcase) == $blockHash and
      any(.logs[]; (.address | ascii_downcase) == $kms and
        ((.topics[0] // "") | ascii_downcase) == $topic and
        (.data | ascii_downcase) == $data)
    ' <<<"$receipt" >/dev/null || {
      echo "KMS registration receipt/status/AppRegistered log does not match the exact release." >&2
      exit 1
    }
  jq -e --arg kms "$(lower "$EMAIL_ORACLE_KMS_ADDRESS")" --arg input "$(lower "$expected_input")" '
    . != null and (.to | ascii_downcase) == $kms and (.input | ascii_downcase) == $input
  ' <<<"$transaction" >/dev/null || {
    echo "KMS registration transaction input is not registerApp(EmailOracleAuth)." >&2
    exit 1
  }
  jq -e --arg blockHash "$(lower "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH")" '
    . != null and (.hash | ascii_downcase) == $blockHash
  ' <<<"$block" >/dev/null || {
    echo "KMS registration block hash is not canonical at the configured block." >&2
    exit 1
  }

  if [ "$(cast call "$EMAIL_ORACLE_KMS_ADDRESS" 'registeredApps(address)(bool)' "$EMAIL_ORACLE_AUTH_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")" != "true" ]; then
    echo "Dstack KMS registeredApps readback is not true." >&2
    exit 1
  fi
  stored_implementation="$(cast storage "$EMAIL_ORACLE_KMS_ADDRESS" "$EIP1967_IMPLEMENTATION_SLOT" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  stored_implementation="0x${stored_implementation: -40}"
  if [ "$(lower "$stored_implementation")" != "$(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS")" ]; then
    echo "KMS EIP-1967 implementation slot does not match the verified implementation." >&2
    exit 1
  fi
  if [ "$(lower "$(cast codehash "$EMAIL_ORACLE_KMS_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")")" != "$(lower "$EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH")" ] \
    || [ "$(lower "$(cast codehash "$EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")")" != "$(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH")" ]; then
    echo "Live KMS proxy or implementation runtime does not match the reviewed code hashes." >&2
    exit 1
  fi
}

expected_phase_actions() {
  case "$EMAIL_ORACLE_RELEASE_PHASE" in
    1) jq -cn '["proposeOracleComposeHash", "addDevice", "setConsumerManager", "addConsumerComposeHash"]' ;;
    2) jq -cn '["activateOracleComposeHash", "freezeOracleCodeAuth"]' ;;
    3) jq -cn '["proposeKmsBinding"]' ;;
    4) jq -cn '["activateAndFreezeKmsBinding", "freezeConsumerManagerAdditions", "freezeConsumerRegistry"]' ;;
  esac
}

expected_prior_release_actions() {
  case "$EMAIL_ORACLE_RELEASE_PHASE" in
    1) jq -cn '[]' ;;
    2) jq -cn '[
      {phase:1,actionIndex:0,action:"proposeOracleComposeHash"},
      {phase:1,actionIndex:1,action:"addDevice"},
      {phase:1,actionIndex:2,action:"setConsumerManager"},
      {phase:1,actionIndex:3,action:"addConsumerComposeHash"}
    ]' ;;
    3) jq -cn '[
      {phase:1,actionIndex:0,action:"proposeOracleComposeHash"},
      {phase:1,actionIndex:1,action:"addDevice"},
      {phase:1,actionIndex:2,action:"setConsumerManager"},
      {phase:1,actionIndex:3,action:"addConsumerComposeHash"},
      {phase:2,actionIndex:0,action:"activateOracleComposeHash"},
      {phase:2,actionIndex:1,action:"freezeOracleCodeAuth"}
    ]' ;;
    4) jq -cn '[
      {phase:1,actionIndex:0,action:"proposeOracleComposeHash"},
      {phase:1,actionIndex:1,action:"addDevice"},
      {phase:1,actionIndex:2,action:"setConsumerManager"},
      {phase:1,actionIndex:3,action:"addConsumerComposeHash"},
      {phase:2,actionIndex:0,action:"activateOracleComposeHash"},
      {phase:2,actionIndex:1,action:"freezeOracleCodeAuth"},
      {phase:3,actionIndex:0,action:"proposeKmsBinding"}
    ]' ;;
  esac
}

collect_accepted_release_actions() {
  if [ ! -f "$RUN_PATH" ] || [ -L "$RUN_PATH" ]; then
    echo "Missing or unsafe Forge broadcast receipt at $RUN_PATH." >&2
    exit 1
  fi
  local expected_actions broadcast_actions
  expected_actions="$(expected_phase_actions)"
  if ! broadcast_actions="$(jq -ce \
    --argjson expected "$expected_actions" \
    --arg auth "$(lower "$EMAIL_ORACLE_AUTH_ADDRESS")" \
    --arg operator "$(lower "$DEPLOYMENT_OPERATOR")" \
    --arg source "$RELEASE_SHA" \
    --argjson startedAt "$BROADCAST_STARTED_AT_MS" '
      (.commit | ascii_downcase) as $commit |
      if .chain != 84532
        or (.timestamp | type) != "number" or .timestamp < $startedAt
        or (.pending | type) != "array" or (.pending | length) != 0
        or ($commit | test("^[0-9a-f]{7,40}$") | not)
        or ($source | startswith($commit) | not)
        or (.transactions | type) != "array"
        or ([.transactions[].function | split("(")[0]] != $expected)
        or ([.transactions[].hash] | unique | length) != ($expected | length)
        or (.transactions | all(
          .transactionType == "CALL" and
          .contractName == "EmailOracleAuth" and
          (.hash | type == "string" and test("^0x[0-9a-f]{64}$") and . != ("0x" + ("0" * 64))) and
          ((.transaction.from // "") | ascii_downcase) == $operator and
          ((.transaction.to // "") | ascii_downcase) == $auth and
          (.transaction.input | type == "string" and test("^0x[0-9a-f]+$") and length >= 10)
        ) | not)
      then error("Forge broadcast artifact does not describe the exact ordered EmailOracleAuth phase")
      else [range(0; $expected | length) as $index | {
        action: $expected[$index],
        transactionHash: .transactions[$index].hash,
        input: .transactions[$index].transaction.input
      }]
      end
    ' "$RUN_PATH")"; then
    echo "Forge broadcast artifact is stale, incomplete, or does not match this exact Email release phase." >&2
    exit 1
  fi

  ACTION_RECEIPTS_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-email-release-actions.XXXXXX")"
  chmod 600 "$ACTION_RECEIPTS_PATH"
  local action tx expected_input receipt transaction block_hex block_number block_hash canonical_block block_timestamp_hex block_timestamp
  while IFS=$'\t' read -r action tx expected_input; do
    receipt="$(cast rpc --rpc-url "$BASE_SEPOLIA_RPC_URL" eth_getTransactionReceipt "$tx" | read_rpc_object)"
    transaction="$(cast rpc --rpc-url "$BASE_SEPOLIA_RPC_URL" eth_getTransactionByHash "$tx" | read_rpc_object)"
    if ! jq -e \
      --arg tx "$(lower "$tx")" \
      --arg auth "$(lower "$EMAIL_ORACLE_AUTH_ADDRESS")" \
      --arg operator "$(lower "$DEPLOYMENT_OPERATOR")" '
        . != null and
        ((.transactionHash // "") | ascii_downcase) == $tx and
        ((.to // "") | ascii_downcase) == $auth and
        ((.from // "") | ascii_downcase) == $operator and
        .status == "0x1" and
        (.blockNumber | type == "string" and test("^0x[0-9a-f]+$")) and
        (.blockHash | type == "string" and test("^0x[0-9a-f]{64}$") and . != ("0x" + ("0" * 64)))
      ' <<<"$receipt" >/dev/null; then
      echo "Email release action receipt is missing, failed, or bound to the wrong roles." >&2
      exit 1
    fi
    block_hex="$(jq -er '.blockNumber' <<<"$receipt")"
    block_hash="$(lower "$(jq -er '.blockHash' <<<"$receipt")")"
    if ! jq -e \
      --arg tx "$(lower "$tx")" \
      --arg auth "$(lower "$EMAIL_ORACLE_AUTH_ADDRESS")" \
      --arg operator "$(lower "$DEPLOYMENT_OPERATOR")" \
      --arg input "$(lower "$expected_input")" \
      --arg blockNumber "$(lower "$block_hex")" \
      --arg blockHash "$block_hash" '
        . != null and
        ((.hash // "") | ascii_downcase) == $tx and
        ((.to // "") | ascii_downcase) == $auth and
        ((.from // "") | ascii_downcase) == $operator and
        ((.input // "") | ascii_downcase) == $input and
        ((.blockNumber // "") | ascii_downcase) == $blockNumber and
        ((.blockHash // "") | ascii_downcase) == $blockHash
      ' <<<"$transaction" >/dev/null; then
      echo "Live Email release transaction does not match the accepted Forge action." >&2
      exit 1
    fi
    canonical_block="$(cast rpc --rpc-url "$BASE_SEPOLIA_RPC_URL" eth_getBlockByNumber "$block_hex" false | read_rpc_object)"
    if ! jq -e --arg blockHash "$block_hash" '
      . != null and
      ((.hash // "") | ascii_downcase) == $blockHash and
      (.timestamp | type == "string" and test("^0x[0-9a-f]+$"))
    ' <<<"$canonical_block" >/dev/null; then
      echo "Email release action is not in the canonical configured block." >&2
      exit 1
    fi
    block_number="$(cast to-dec "$block_hex")"
    block_timestamp_hex="$(jq -er '.timestamp' <<<"$canonical_block")"
    block_timestamp="$(cast to-dec "$block_timestamp_hex")"
    if [[ ! "$block_number" =~ ^[1-9][0-9]*$ ]] || [[ ! "$block_timestamp" =~ ^[1-9][0-9]*$ ]]; then
      echo "Email release action block number or timestamp is invalid." >&2
      exit 1
    fi
    jq -cn \
      --arg action "$action" \
      --arg transactionHash "$(lower "$tx")" \
      --argjson blockNumber "$block_number" \
      --arg blockHash "$block_hash" \
      --argjson blockTimestamp "$block_timestamp" \
      '{action:$action,transactionHash:$transactionHash,blockNumber:$blockNumber,blockHash:$blockHash,blockTimestamp:$blockTimestamp}' \
      >> "$ACTION_RECEIPTS_PATH"
  done < <(jq -r '.[] | [.action, .transactionHash, .input] | @tsv' <<<"$broadcast_actions")

  jq -sc '.' "$ACTION_RECEIPTS_PATH"
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
  EMAIL_ORACLE_UPGRADE_DELAY \
  EMAIL_ORACLE_AUTH_ADDRESS \
  EMAIL_ORACLE_RUNTIME_CODE_HASH \
  EMAIL_ORACLE_COMPOSE_HASH \
  EMAIL_ORACLE_DEVICE_ID \
  EMAIL_ORACLE_CONSUMER_APP_ID \
  EMAIL_ORACLE_CONSUMER_COMPOSE_HASH \
  EMAIL_ORACLE_RELEASE_PHASE; do
  require_env "$name"
done

BROADCAST="${BROADCAST:-false}"
validate_bool BROADCAST "$BROADCAST"
if [[ ! "$EMAIL_ORACLE_RELEASE_PHASE" =~ ^[1234]$ ]]; then
  echo "EMAIL_ORACLE_RELEASE_PHASE must be exactly 1, 2, 3, or 4." >&2
  exit 1
fi
for name in DEPLOYMENT_OPERATOR EMAIL_ORACLE_AUTH_ADDRESS EMAIL_ORACLE_CONSUMER_APP_ID; do
  validate_address "$name" "${!name}"
done
for name in EMAIL_ORACLE_RUNTIME_CODE_HASH EMAIL_ORACLE_COMPOSE_HASH EMAIL_ORACLE_DEVICE_ID EMAIL_ORACLE_CONSUMER_COMPOSE_HASH; do
  validate_bytes32 "$name" "${!name}"
done
if [ "$(lower "$DEPLOYMENT_OPERATOR")" = "$(lower "$EMAIL_ORACLE_CONSUMER_APP_ID")" ]; then
  echo "Email consumer/main-CVM identity must be independent of DEPLOYMENT_OPERATOR." >&2
  exit 1
fi


operator_policy_project_and_validate
operator_policy_assert_public_env contractEnv EMAIL_ORACLE_UPGRADE_DELAY
operator_policy_assert_public_env \
  postDeployEnv \
  EMAIL_ORACLE_CONSUMER_APP_ID \
  TINKER_ENCUMBRANCE_RELEASE_MANAGER
operator_policy_assert_public_env \
  postDeployEnv \
  EMAIL_ORACLE_COMPOSE_HASH \
  TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH
operator_policy_assert_public_env \
  postDeployEnv \
  EMAIL_ORACLE_CONSUMER_COMPOSE_HASH \
  TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH
require_env OPERATOR_POLICY_FINAL_AUTHORITY_SHA256
require_env OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256
validate_sha256 OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256"
validate_sha256 OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"
validate_review_envelope_file
validate_authority_review_envelope
validate_deployment_ledger
validate_deployment_ledger_phase_history
LEDGER_PRE_BROADCAST_SHA256="$(deployment_ledger_sha256)"

if [ "$EMAIL_ORACLE_RELEASE_PHASE" -ge 3 ]; then
  for name in \
    EMAIL_ORACLE_KMS_ADDRESS \
    EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH \
    EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS \
    EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH \
    EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH \
    EMAIL_ORACLE_KMS_REGISTRATION_BLOCK \
    EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH \
    EMAIL_ORACLE_BOOT_INSTANCE_ID \
    EMAIL_ORACLE_BOOT_MR_AGGREGATED \
    EMAIL_ORACLE_BOOT_MR_SYSTEM \
    EMAIL_ORACLE_BOOT_OS_IMAGE_HASH \
    EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256; do
    require_env "$name"
  done
  for name in EMAIL_ORACLE_KMS_ADDRESS EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS EMAIL_ORACLE_BOOT_INSTANCE_ID; do
    validate_address "$name" "${!name}"
  done
  for name in \
    EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH \
    EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH \
    EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH \
    EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH \
    EMAIL_ORACLE_BOOT_MR_AGGREGATED \
    EMAIL_ORACLE_BOOT_MR_SYSTEM \
    EMAIL_ORACLE_BOOT_OS_IMAGE_HASH \
    EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256; do
    validate_bytes32 "$name" "${!name}"
  done
  if [[ ! "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK" =~ ^[1-9][0-9]*$ ]]; then
    echo "EMAIL_ORACLE_KMS_REGISTRATION_BLOCK must be a positive decimal block." >&2
    exit 1
  fi
  require_exact_external_evidence
  verify_live_kms_registration
fi

if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  echo "Email release governance is restricted to the Foundry keystore account named dev." >&2
  exit 1
fi
if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
  echo "Foundry keystore account dev was not found. Use /cast-wallet first." >&2
  exit 1
fi

live_chain_id="$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$live_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing email release: RPC chainId $live_chain_id is not Base Sepolia $CHAIN_ID." >&2
  exit 1
fi
if [ "$(lower "$(cast codehash "$EMAIL_ORACLE_AUTH_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")")" != "$(lower "$EMAIL_ORACLE_RUNTIME_CODE_HASH")" ]; then
  echo "EmailOracleAuth runtime code does not match the reviewed release hash." >&2
  exit 1
fi
live_owner="$(cast call "$EMAIL_ORACLE_AUTH_ADDRESS" 'owner()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_owner="$(cast call "$EMAIL_ORACLE_AUTH_ADDRESS" 'pendingOwner()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(lower "$live_owner")" != "$(lower "$DEPLOYMENT_OPERATOR")" ] || [ "$(lower "$pending_owner")" != "$ZERO_ADDRESS" ]; then
  echo "EmailOracleAuth owner/pending-owner state does not match the release operator." >&2
  exit 1
fi
live_upgrade_delay="$(cast call "$EMAIL_ORACLE_AUTH_ADDRESS" 'ORACLE_UPGRADE_DELAY()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
if [ "$live_upgrade_delay" != "$EMAIL_ORACLE_UPGRADE_DELAY" ]; then
  echo "EmailOracleAuth upgrade delay does not match the reviewed operator policy." >&2
  exit 1
fi

if [ "$BROADCAST" = "true" ]; then
  check_release_provenance
  if [ "$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")" = "0" ]; then
    echo "DEPLOYMENT_OPERATOR has no Base Sepolia ETH for governance gas." >&2
    exit 1
  fi
fi

echo "== EmailOracleAuth release phase $EMAIL_ORACLE_RELEASE_PHASE =="
echo "Chain ID:          $live_chain_id"
echo "Keystore account:  dev"
echo "Operator:          $DEPLOYMENT_OPERATOR"
echo "EmailOracleAuth:   $EMAIL_ORACLE_AUTH_ADDRESS"
echo "Consumer/main TEE: $EMAIL_ORACLE_CONSUMER_APP_ID"
echo "Broadcast:         $BROADCAST"
if [ "$EMAIL_ORACLE_RELEASE_PHASE" -ge 3 ]; then
  echo "Dstack KMS:        $EMAIL_ORACLE_KMS_ADDRESS"
  echo "KMS registration:  $EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH"
  echo "External proof:    $EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256"
fi

cd "$CONTRACTS_DIR"
forge build --sizes
forge test --match-path test/EmailOracleAuth.t.sol
forge test --match-path test/ConfigureEmailOracleRelease.t.sol

echo
echo "== Dry run =="
forge script script/ConfigureEmailOracleRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

if [ "$BROADCAST" != "true" ]; then
  echo "Dry run complete; no chain state changed. Missing real external evidence always remains a hard phase-3/4 blocker."
  exit 0
fi

operator_policy_acquire_release_ceremony_lock email_oracle_release

check_release_provenance
validate_deployment_ledger
validate_deployment_ledger_phase_history
LEDGER_PRE_BROADCAST_SHA256="$(deployment_ledger_sha256)"
unlocked_signer="$(cast wallet address --account dev)"
if [ "$(lower "$unlocked_signer")" != "$(lower "$DEPLOYMENT_OPERATOR")" ]; then
  echo "The unlocked dev keystore does not match DEPLOYMENT_OPERATOR." >&2
  exit 1
fi
PRE_PHASE4_TARGET_BOOT_INFO_HASH="$ZERO_BYTES32"
if [ "$EMAIL_ORACLE_RELEASE_PHASE" = "4" ]; then
  PRE_PHASE4_TARGET_BOOT_INFO_HASH="$(lower "$(read_value 'pendingTargetBootInfoHash()(bytes32)')")"
  if [ "$PRE_PHASE4_TARGET_BOOT_INFO_HASH" = "$ZERO_BYTES32" ]; then
    echo "Phase 4 requires a nonzero pending target boot commitment." >&2
    exit 1
  fi
fi

echo
echo "== Broadcast exact timelocked phase =="
BROADCAST_STARTED_AT_MS="$(($(date +%s) * 1000))"
forge script script/ConfigureEmailOracleRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --account dev \
  --broadcast \
  --slow

live_owner="$(lower "$(read_value 'owner()(address)')")"
pending_owner="$(lower "$(read_value 'pendingOwner()(address)')")"
live_upgrade_delay="$(read_uint 'ORACLE_UPGRADE_DELAY()(uint256)')"
allow_any="$(read_value 'allowAnyDevice()(bool)')"
active_compose="$(read_uint 'allowedOracleComposeHashCount()(uint256)')"
pending_compose="$(read_uint 'pendingOracleComposeHashCount()(uint256)')"
device_count="$(read_uint 'allowedDeviceIdCount()(uint256)')"
manager_count="$(read_uint 'consumerManagerCount()(uint256)')"
consumer_count="$(read_uint 'totalConsumerComposeHashCount()(uint256)')"
oracle_frozen="$(read_value 'oracleCodeFrozen()(bool)')"
kms_frozen="$(read_value 'kmsBindingFrozen()(bool)')"
manager_frozen="$(read_value 'consumerManagerAdditionsFrozen()(bool)')"
consumer_frozen="$(read_value 'consumerRegistryFrozen()(bool)')"
release_ready="$(read_value 'releaseConfigurationReady()(bool)')"
allowed_compose="$(read_value 'allowedOracleComposeHashes(bytes32)(bool)' "$EMAIL_ORACLE_COMPOSE_HASH")"
pending_compose_at="$(read_uint 'pendingOracleComposeHashes(bytes32)(uint256)' "$EMAIL_ORACLE_COMPOSE_HASH")"
allowed_device="$(read_value 'allowedDeviceIds(bytes32)(bool)' "$EMAIL_ORACLE_DEVICE_ID")"
manager_allowed="$(read_value 'consumerManagers(address)(bool)' "$EMAIL_ORACLE_CONSUMER_APP_ID")"
consumer_compose_count="$(read_uint 'consumerComposeHashCount(address)(uint256)' "$EMAIL_ORACLE_CONSUMER_APP_ID")"
consumer_authorized="$(read_value 'isConsumerAuthorized(address,bytes32)(bool)' "$EMAIL_ORACLE_CONSUMER_APP_ID" "$EMAIL_ORACLE_CONSUMER_COMPOSE_HASH")"
consumer_revoked="$(read_value 'consumerEmergencyRevoked(address)(bool)' "$EMAIL_ORACLE_CONSUMER_APP_ID")"
release_oracle_compose="$(lower "$(read_value 'releaseOracleComposeHash()(bytes32)')")"
release_device="$(lower "$(read_value 'releaseDeviceId()(bytes32)')")"
release_consumer_manager="$(lower "$(read_value 'releaseConsumerManager()(address)')")"
release_consumer_app="$(lower "$(read_value 'releaseConsumerAppId()(address)')")"
release_consumer_compose="$(lower "$(read_value 'releaseConsumerComposeHash()(bytes32)')")"
kms_contract="$(lower "$(read_value 'kmsContract()(address)')")"
kms_runtime_hash="$(lower "$(read_value 'kmsRuntimeCodeHash()(bytes32)')")"
kms_implementation="$(lower "$(read_value 'kmsImplementation()(address)')")"
kms_implementation_runtime_hash="$(lower "$(read_value 'kmsImplementationRuntimeCodeHash()(bytes32)')")"
kms_registration_tx="$(lower "$(read_value 'kmsRegistrationTxHash()(bytes32)')")"
kms_registration_block="$(read_uint 'kmsRegistrationBlock()(uint64)')"
kms_registration_block_hash="$(lower "$(read_value 'kmsRegistrationBlockHash()(bytes32)')")"
target_boot_info_hash="$(lower "$(read_value 'targetBootInfoHash()(bytes32)')")"
restart_proof_hash="$(lower "$(read_value 'restartKeyDerivationProofHash()(bytes32)')")"
pending_kms_contract="$(lower "$(read_value 'pendingKmsContract()(address)')")"
pending_kms_runtime_hash="$(lower "$(read_value 'pendingKmsRuntimeCodeHash()(bytes32)')")"
pending_kms_implementation="$(lower "$(read_value 'pendingKmsImplementation()(address)')")"
pending_kms_implementation_runtime_hash="$(lower "$(read_value 'pendingKmsImplementationRuntimeCodeHash()(bytes32)')")"
pending_kms_registration_tx="$(lower "$(read_value 'pendingKmsRegistrationTxHash()(bytes32)')")"
pending_kms_registration_block="$(read_uint 'pendingKmsRegistrationBlock()(uint64)')"
pending_kms_registration_block_hash="$(lower "$(read_value 'pendingKmsRegistrationBlockHash()(bytes32)')")"
pending_target_boot_info_hash="$(lower "$(read_value 'pendingTargetBootInfoHash()(bytes32)')")"
pending_restart_proof_hash="$(lower "$(read_value 'pendingRestartKeyDerivationProofHash()(bytes32)')")"
pending_kms_activates_at="$(read_uint 'pendingKmsBindingActivatesAt()(uint256)')"

require_exact_state owner "$live_owner" "$DEPLOYMENT_OPERATOR"
require_exact_state pendingOwner "$pending_owner" "$ZERO_ADDRESS"
require_exact_state oracleUpgradeDelay "$live_upgrade_delay" "$EMAIL_ORACLE_UPGRADE_DELAY"
require_exact_state allowAnyDevice "$allow_any" false
require_exact_state allowedDeviceIdCount "$device_count" 1
require_exact_state consumerManagerCount "$manager_count" 1
require_exact_state totalConsumerComposeHashCount "$consumer_count" 1
require_exact_state deviceBinding "$allowed_device" true
require_exact_state consumerManagerBinding "$manager_allowed" true
require_exact_state consumerComposeHashCount "$consumer_compose_count" 1
require_exact_state consumerAuthorization "$consumer_authorized" true
require_exact_state consumerEmergencyRevoked "$consumer_revoked" false

zero_active_kms="$ZERO_ADDRESS $ZERO_BYTES32 $ZERO_ADDRESS $ZERO_BYTES32 $ZERO_BYTES32 0 $ZERO_BYTES32 $ZERO_BYTES32 $ZERO_BYTES32"
actual_active_kms="$kms_contract $kms_runtime_hash $kms_implementation $kms_implementation_runtime_hash $kms_registration_tx $kms_registration_block $kms_registration_block_hash $target_boot_info_hash $restart_proof_hash"
zero_pending_kms="$ZERO_ADDRESS $ZERO_BYTES32 $ZERO_ADDRESS $ZERO_BYTES32 $ZERO_BYTES32 0 $ZERO_BYTES32 $ZERO_BYTES32 $ZERO_BYTES32 0"
actual_pending_kms="$pending_kms_contract $pending_kms_runtime_hash $pending_kms_implementation $pending_kms_implementation_runtime_hash $pending_kms_registration_tx $pending_kms_registration_block $pending_kms_registration_block_hash $pending_target_boot_info_hash $pending_restart_proof_hash $pending_kms_activates_at"

case "$EMAIL_ORACLE_RELEASE_PHASE" in
  1)
    require_exact_state phaseOneSummary \
      "$active_compose $pending_compose $allowed_compose $oracle_frozen $kms_frozen $manager_frozen $consumer_frozen $release_ready" \
      "0 1 false false false false false false"
    if [[ ! "$pending_compose_at" =~ ^[1-9][0-9]*$ ]]; then
      echo "Phase 1 did not retain a positive oracle compose activation time." >&2
      exit 1
    fi
    require_exact_state releaseOracleComposeHash "$release_oracle_compose" "$ZERO_BYTES32"
    require_exact_state releaseDeviceId "$release_device" "$ZERO_BYTES32"
    require_exact_state releaseConsumerManager "$release_consumer_manager" "$ZERO_ADDRESS"
    require_exact_state releaseConsumerAppId "$release_consumer_app" "$ZERO_ADDRESS"
    require_exact_state releaseConsumerComposeHash "$release_consumer_compose" "$ZERO_BYTES32"
    require_exact_state activeKmsBinding "$actual_active_kms" "$zero_active_kms"
    require_exact_state pendingKmsBinding "$actual_pending_kms" "$zero_pending_kms"
    ledger_status="deployed_oracle_policy_pending_timelock_consumer_bound"
    policy_state="oracle_policy_pending_timelock_consumer_bound"
    ;;
  2)
    require_exact_state phaseTwoSummary \
      "$active_compose $pending_compose $pending_compose_at $allowed_compose $oracle_frozen $kms_frozen $manager_frozen $consumer_frozen $release_ready" \
      "1 0 0 true true false false false false"
    require_exact_state releaseOracleComposeHash "$release_oracle_compose" "$EMAIL_ORACLE_COMPOSE_HASH"
    require_exact_state releaseDeviceId "$release_device" "$EMAIL_ORACLE_DEVICE_ID"
    require_exact_state releaseConsumerManager "$release_consumer_manager" "$ZERO_ADDRESS"
    require_exact_state releaseConsumerAppId "$release_consumer_app" "$ZERO_ADDRESS"
    require_exact_state releaseConsumerComposeHash "$release_consumer_compose" "$ZERO_BYTES32"
    require_exact_state activeKmsBinding "$actual_active_kms" "$zero_active_kms"
    require_exact_state pendingKmsBinding "$actual_pending_kms" "$zero_pending_kms"
    ledger_status="deployed_oracle_policy_frozen_kms_unbound"
    policy_state="oracle_policy_frozen_kms_unbound"
    ;;
  3)
    require_exact_state phaseThreeSummary \
      "$active_compose $pending_compose $pending_compose_at $allowed_compose $oracle_frozen $kms_frozen $manager_frozen $consumer_frozen $release_ready" \
      "1 0 0 true true false false false false"
    require_exact_state releaseOracleComposeHash "$release_oracle_compose" "$EMAIL_ORACLE_COMPOSE_HASH"
    require_exact_state releaseDeviceId "$release_device" "$EMAIL_ORACLE_DEVICE_ID"
    require_exact_state releaseConsumerManager "$release_consumer_manager" "$ZERO_ADDRESS"
    require_exact_state releaseConsumerAppId "$release_consumer_app" "$ZERO_ADDRESS"
    require_exact_state releaseConsumerComposeHash "$release_consumer_compose" "$ZERO_BYTES32"
    require_exact_state activeKmsBinding "$actual_active_kms" "$zero_active_kms"
    expected_pending_kms="$(lower "$EMAIL_ORACLE_KMS_ADDRESS") $(lower "$EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH") $(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS") $(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH") $(lower "$EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH") $EMAIL_ORACLE_KMS_REGISTRATION_BLOCK $(lower "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH")"
    require_exact_state pendingKmsBindingPrefix \
      "$pending_kms_contract $pending_kms_runtime_hash $pending_kms_implementation $pending_kms_implementation_runtime_hash $pending_kms_registration_tx $pending_kms_registration_block $pending_kms_registration_block_hash" \
      "$expected_pending_kms"
    require_exact_state pendingRestartProof "$pending_restart_proof_hash" "$EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256"
    if [ "$pending_target_boot_info_hash" = "$ZERO_BYTES32" ] || [[ ! "$pending_kms_activates_at" =~ ^[1-9][0-9]*$ ]]; then
      echo "Phase 3 did not retain nonzero target-boot and KMS-timelock commitments." >&2
      exit 1
    fi
    ledger_status="deployed_kms_binding_pending_timelock"
    policy_state="oracle_policy_frozen_kms_binding_pending_timelock"
    verify_live_kms_registration
    ;;
  4)
    require_exact_state phaseFourSummary \
      "$active_compose $pending_compose $pending_compose_at $allowed_compose $oracle_frozen $kms_frozen $manager_frozen $consumer_frozen $release_ready" \
      "1 0 0 true true true true true true"
    require_exact_state releaseOracleComposeHash "$release_oracle_compose" "$EMAIL_ORACLE_COMPOSE_HASH"
    require_exact_state releaseDeviceId "$release_device" "$EMAIL_ORACLE_DEVICE_ID"
    require_exact_state releaseConsumerManager "$release_consumer_manager" "$EMAIL_ORACLE_CONSUMER_APP_ID"
    require_exact_state releaseConsumerAppId "$release_consumer_app" "$EMAIL_ORACLE_CONSUMER_APP_ID"
    require_exact_state releaseConsumerComposeHash "$release_consumer_compose" "$EMAIL_ORACLE_CONSUMER_COMPOSE_HASH"
    expected_active_kms="$(lower "$EMAIL_ORACLE_KMS_ADDRESS") $(lower "$EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH") $(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS") $(lower "$EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH") $(lower "$EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH") $EMAIL_ORACLE_KMS_REGISTRATION_BLOCK $(lower "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH") $PRE_PHASE4_TARGET_BOOT_INFO_HASH $(lower "$EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256")"
    require_exact_state activeKmsBinding "$actual_active_kms" "$expected_active_kms"
    require_exact_state pendingKmsBinding "$actual_pending_kms" "$zero_pending_kms"
    ledger_status="deployed_exact_email_release_frozen_ready"
    policy_state="exact_email_release_frozen_ready"
    verify_live_kms_registration
    ;;
esac

accepted_actions="$(collect_accepted_release_actions)"
validate_deployment_ledger
if [ "$(deployment_ledger_sha256)" != "$LEDGER_PRE_BROADCAST_SHA256" ]; then
  echo "Deployment ledger changed during the Email release broadcast; refusing to overwrite concurrent evidence." >&2
  exit 1
fi

post_state="$(jq -cn \
  --arg status "$ledger_status" \
  --arg policyState "$policy_state" \
  --arg owner "$live_owner" \
  --arg pendingOwner "$pending_owner" \
  --argjson oracleUpgradeDelaySeconds "$live_upgrade_delay" \
  --argjson allowAnyDevice "$allow_any" \
  --argjson oracleCodeFrozen "$oracle_frozen" \
  --argjson consumerRegistryFrozen "$consumer_frozen" \
  --argjson consumerManagerAdditionsFrozen "$manager_frozen" \
  --argjson kmsBindingFrozen "$kms_frozen" \
  --argjson allowedOracleComposeHashCount "$active_compose" \
  --argjson pendingOracleComposeHashCount "$pending_compose" \
  --argjson allowedDeviceIdCount "$device_count" \
  --argjson consumerManagerCount "$manager_count" \
  --argjson totalConsumerComposeHashCount "$consumer_count" \
  --arg releaseOracleComposeHash "$release_oracle_compose" \
  --arg releaseDeviceId "$release_device" \
  --arg releaseConsumerManager "$release_consumer_manager" \
  --arg releaseConsumerAppId "$release_consumer_app" \
  --arg releaseConsumerComposeHash "$release_consumer_compose" \
  --argjson oracleComposeHashAllowed "$allowed_compose" \
  --argjson oracleComposeHashPendingActivatesAt "$pending_compose_at" \
  --argjson deviceIdAllowed "$allowed_device" \
  --argjson consumerManagerAllowed "$manager_allowed" \
  --argjson consumerComposeHashCount "$consumer_compose_count" \
  --argjson consumerAuthorized "$consumer_authorized" \
  --argjson consumerEmergencyRevoked "$consumer_revoked" \
  --arg kmsContract "$kms_contract" \
  --arg kmsRuntimeCodeHash "$kms_runtime_hash" \
  --arg kmsImplementation "$kms_implementation" \
  --arg kmsImplementationRuntimeCodeHash "$kms_implementation_runtime_hash" \
  --arg kmsRegistrationTxHash "$kms_registration_tx" \
  --argjson kmsRegistrationBlock "$kms_registration_block" \
  --arg kmsRegistrationBlockHash "$kms_registration_block_hash" \
  --arg targetBootInfoHash "$target_boot_info_hash" \
  --arg restartKeyDerivationProofHash "$restart_proof_hash" \
  --arg pendingKmsContract "$pending_kms_contract" \
  --arg pendingKmsRuntimeCodeHash "$pending_kms_runtime_hash" \
  --arg pendingKmsImplementation "$pending_kms_implementation" \
  --arg pendingKmsImplementationRuntimeCodeHash "$pending_kms_implementation_runtime_hash" \
  --arg pendingKmsRegistrationTxHash "$pending_kms_registration_tx" \
  --argjson pendingKmsRegistrationBlock "$pending_kms_registration_block" \
  --arg pendingKmsRegistrationBlockHash "$pending_kms_registration_block_hash" \
  --arg pendingTargetBootInfoHash "$pending_target_boot_info_hash" \
  --arg pendingRestartKeyDerivationProofHash "$pending_restart_proof_hash" \
  --argjson pendingKmsBindingActivatesAt "$pending_kms_activates_at" \
  --argjson releaseConfigurationReady "$release_ready" '
    {
      status:$status,
      policyState:$policyState,
      owner:$owner,
      pendingOwner:$pendingOwner,
      oracleUpgradeDelaySeconds:$oracleUpgradeDelaySeconds,
      allowAnyDevice:$allowAnyDevice,
      oracleCodeFrozen:$oracleCodeFrozen,
      consumerRegistryFrozen:$consumerRegistryFrozen,
      consumerManagerAdditionsFrozen:$consumerManagerAdditionsFrozen,
      kmsBindingFrozen:$kmsBindingFrozen,
      allowedOracleComposeHashCount:$allowedOracleComposeHashCount,
      pendingOracleComposeHashCount:$pendingOracleComposeHashCount,
      allowedDeviceIdCount:$allowedDeviceIdCount,
      consumerManagerCount:$consumerManagerCount,
      totalConsumerComposeHashCount:$totalConsumerComposeHashCount,
      releaseOracleComposeHash:$releaseOracleComposeHash,
      releaseDeviceId:$releaseDeviceId,
      releaseConsumerManager:$releaseConsumerManager,
      releaseConsumerAppId:$releaseConsumerAppId,
      releaseConsumerComposeHash:$releaseConsumerComposeHash,
      oracleComposeHashAllowed:$oracleComposeHashAllowed,
      oracleComposeHashPendingActivatesAt:$oracleComposeHashPendingActivatesAt,
      deviceIdAllowed:$deviceIdAllowed,
      consumerManagerAllowed:$consumerManagerAllowed,
      consumerComposeHashCount:$consumerComposeHashCount,
      consumerAuthorized:$consumerAuthorized,
      consumerEmergencyRevoked:$consumerEmergencyRevoked,
      kmsContract:$kmsContract,
      kmsRuntimeCodeHash:$kmsRuntimeCodeHash,
      kmsImplementation:$kmsImplementation,
      kmsImplementationRuntimeCodeHash:$kmsImplementationRuntimeCodeHash,
      kmsRegistrationTxHash:$kmsRegistrationTxHash,
      kmsRegistrationBlock:$kmsRegistrationBlock,
      kmsRegistrationBlockHash:$kmsRegistrationBlockHash,
      targetBootInfoHash:$targetBootInfoHash,
      restartKeyDerivationProofHash:$restartKeyDerivationProofHash,
      pendingKmsContract:$pendingKmsContract,
      pendingKmsRuntimeCodeHash:$pendingKmsRuntimeCodeHash,
      pendingKmsImplementation:$pendingKmsImplementation,
      pendingKmsImplementationRuntimeCodeHash:$pendingKmsImplementationRuntimeCodeHash,
      pendingKmsRegistrationTxHash:$pendingKmsRegistrationTxHash,
      pendingKmsRegistrationBlock:$pendingKmsRegistrationBlock,
      pendingKmsRegistrationBlockHash:$pendingKmsRegistrationBlockHash,
      pendingTargetBootInfoHash:$pendingTargetBootInfoHash,
      pendingRestartKeyDerivationProofHash:$pendingRestartKeyDerivationProofHash,
      pendingKmsBindingActivatesAt:$pendingKmsBindingActivatesAt,
      releaseConfigurationReady:$releaseConfigurationReady
    }
  ')"

recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LEDGER_TEMP_PATH="$(mktemp "${MANIFEST_PATH}.tmp.XXXXXX")"
chmod 600 "$LEDGER_TEMP_PATH"
if ! jq \
  --arg emailOracleAuthAddress "$(lower "$EMAIL_ORACLE_AUTH_ADDRESS")" \
  --arg runtimeCodeHash "$(lower "$EMAIL_ORACLE_RUNTIME_CODE_HASH")" \
  --arg sourceCommit "$RELEASE_SHA" \
  --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --argjson phase "$EMAIL_ORACLE_RELEASE_PHASE" \
  --arg recordedAt "$recorded_at" \
  --argjson postState "$post_state" \
  --argjson actionRecords "$accepted_actions" \
  -f "$MANIFEST_FILTER" "$MANIFEST_PATH" > "$LEDGER_TEMP_PATH"; then
  echo "Failed to build the exact Email release ledger update." >&2
  exit 1
fi
if ! jq -e . "$LEDGER_TEMP_PATH" >/dev/null; then
  echo "Email release ledger update is not valid JSON." >&2
  exit 1
fi
if [ "$(deployment_ledger_sha256)" != "$LEDGER_PRE_BROADCAST_SHA256" ]; then
  echo "Deployment ledger changed while rendering Email release evidence; refusing atomic replacement." >&2
  exit 1
fi
operator_policy_durably_replace_release_ledger "$LEDGER_TEMP_PATH" "$MANIFEST_PATH"
rm -f -- "$LEDGER_TEMP_PATH"
LEDGER_TEMP_PATH=""
operator_policy_release_release_ceremony_lock

echo "Phase $EMAIL_ORACLE_RELEASE_PHASE is confirmed on Base Sepolia with exact atomic ledger evidence for every accepted action."
