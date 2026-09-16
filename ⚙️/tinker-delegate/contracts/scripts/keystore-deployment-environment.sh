#!/bin/bash

# Shared data-only environment boundary for production Base Sepolia wrappers
# that can reach the encrypted Foundry account named dev. The wrapper verifies
# this file's canonical identity and custody before sourcing it under
# /bin/bash -p. This file must never be executed directly.

set +x

case $- in
  *p*) ;;
  *)
    echo "The keystore deployment environment boundary requires /bin/bash -p." >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "The keystore deployment environment boundary must only be sourced by a guarded release wrapper." >&2
  exit 1
fi

if [ "${DNAI_KEYSTORE_DEPLOYMENT_ENVIRONMENT_LOADED+x}" = "x" ]; then
  echo "The keystore deployment environment boundary may only be loaded once." >&2
  return 1
fi
readonly DNAI_KEYSTORE_DEPLOYMENT_ENVIRONMENT_LOADED=true

# Preserve caller presence separately from value. In particular, an explicit
# empty value must survive dotenv loading and fail closed instead of becoming
# false. These captures occur before any dotenv bytes are parsed.
readonly DNAI_KEYSTORE_CALLER_BROADCAST_PRESENT="${BROADCAST+x}"
readonly DNAI_KEYSTORE_CALLER_BROADCAST_VALUE="${BROADCAST-}"
readonly DNAI_KEYSTORE_CALLER_VERIFY_PRESENT="${VERIFY+x}"
readonly DNAI_KEYSTORE_CALLER_VERIFY_VALUE="${VERIFY-}"
readonly DNAI_KEYSTORE_CALLER_DEPLOYMENT_MANIFEST_PATH_PRESENT="${DEPLOYMENT_MANIFEST_PATH+x}"
readonly DNAI_KEYSTORE_CALLER_DEPLOYMENT_MANIFEST_PATH_VALUE="${DEPLOYMENT_MANIFEST_PATH-}"

# Reject the reviewed exact aliases and, case-insensitively, every exported or
# dotenv name containing PRIVATE_KEY or MNEMONIC. The only exclusions are the
# two named purpose-scoped CVM ingress keys below; they are scrubbed and never
# forwarded to release tools. Presence is forbidden even for an empty value or
# a path to raw signer material. JUDGE_PRIVATE_KEY and KMS_PRIVATE_KEY remain
# explicit legacy aliases because the repository preflight names them.
DNAI_FORBIDDEN_RAW_SIGNER_ENV_NAMES=(
  PRIVATE_KEY
  DEPLOYER_PRIVATE_KEY
  FOUNDRY_PRIVATE_KEY
  ETH_PRIVATE_KEY
  JUDGE_PRIVATE_KEY
  KMS_PRIVATE_KEY
  ROYALTY_PRIVATE_KEY
  DEPLOYMENT_PRIVATE_KEY
  BASE_SEPOLIA_PRIVATE_KEY
  PRIVATE_KEY_PATH
  DEPLOYER_PRIVATE_KEY_PATH
  FOUNDRY_PRIVATE_KEY_PATH
  ETH_PRIVATE_KEY_PATH
  JUDGE_PRIVATE_KEY_PATH
  KMS_PRIVATE_KEY_PATH
  ROYALTY_PRIVATE_KEY_PATH
  DEPLOYMENT_PRIVATE_KEY_PATH
  BASE_SEPOLIA_PRIVATE_KEY_PATH
  PRIVATE_KEY_FILE
  DEPLOYER_PRIVATE_KEY_FILE
  FOUNDRY_PRIVATE_KEY_FILE
  ETH_PRIVATE_KEY_FILE
  JUDGE_PRIVATE_KEY_FILE
  KMS_PRIVATE_KEY_FILE
  ROYALTY_PRIVATE_KEY_FILE
  DEPLOYMENT_PRIVATE_KEY_FILE
  BASE_SEPOLIA_PRIVATE_KEY_FILE
  PRIVATE_KEY_HEX
  DEPLOYER_PRIVATE_KEY_HEX
  FOUNDRY_PRIVATE_KEY_HEX
  ETH_PRIVATE_KEY_HEX
  JUDGE_PRIVATE_KEY_HEX
  KMS_PRIVATE_KEY_HEX
  ROYALTY_PRIVATE_KEY_HEX
  DEPLOYMENT_PRIVATE_KEY_HEX
  BASE_SEPOLIA_PRIVATE_KEY_HEX
  MNEMONIC
  DEPLOYER_MNEMONIC
  FOUNDRY_MNEMONIC
  ETH_MNEMONIC
  JUDGE_MNEMONIC
  KMS_MNEMONIC
  ROYALTY_MNEMONIC
  DEPLOYMENT_MNEMONIC
  BASE_SEPOLIA_MNEMONIC
  MNEMONIC_PATH
  DEPLOYER_MNEMONIC_PATH
  FOUNDRY_MNEMONIC_PATH
  ETH_MNEMONIC_PATH
  JUDGE_MNEMONIC_PATH
  KMS_MNEMONIC_PATH
  ROYALTY_MNEMONIC_PATH
  DEPLOYMENT_MNEMONIC_PATH
  BASE_SEPOLIA_MNEMONIC_PATH
  MNEMONIC_FILE
  DEPLOYER_MNEMONIC_FILE
  FOUNDRY_MNEMONIC_FILE
  ETH_MNEMONIC_FILE
  JUDGE_MNEMONIC_FILE
  KMS_MNEMONIC_FILE
  ROYALTY_MNEMONIC_FILE
  DEPLOYMENT_MNEMONIC_FILE
  BASE_SEPOLIA_MNEMONIC_FILE
)
readonly DNAI_FORBIDDEN_RAW_SIGNER_ENV_NAMES

# Only documented contract-release inputs may be assigned from the shared
# root dotenv. Other well-formed application/CVM records are safely ignored;
# a name that would overwrite an already-defined wrapper/bootstrap variable is
# rejected. This keeps one shared .env usable without making it executable or
# allowing CONTRACTS_DIR, ACCOUNT, CHAIN_ID, helper paths, or state variables
# to be redirected.
DNAI_ALLOWED_DEPLOYMENT_DOTENV_NAMES=(
  BASE_SEPOLIA_RPC_URL
  BASE_SEPOLIA_SECONDARY_RPC_URL
  BROADCAST
  CHALLENGE_REGISTRY_ADDRESS
  CHALLENGE_REGISTRY_RELEASE_PHASE
  CHALLENGE_REGISTRY_RUNTIME_CODE_HASH
  COMPUTE_METERING_POLICY_SET_HASH
  COMPUTE_RELEASE_PHASE
  COMPUTE_VAULT_ADDRESS
  COMPUTE_VAULT_COMPOSE_HASH
  COMPUTE_VAULT_DEVELOPER
  COMPUTE_VAULT_DEVELOPER_FEE_BPS
  COMPUTE_VAULT_ERC20_ASSET_ADDRESS
  COMPUTE_VAULT_ERC20_PROVIDER
  COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT
  COMPUTE_VAULT_METERING_QVL_VERIFIER
  COMPUTE_VAULT_METERING_VERIFIER
  COMPUTE_VAULT_NATIVE_PROVIDER
  COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT
  COMPUTE_VAULT_RUNTIME_CODE_HASH
  COMPUTE_VAULT_TEE_IDENTITY
  DEPLOYMENT_INTENT_PATH
  DEPLOYMENT_INTENT_SHA256
  DEPLOYMENT_MANIFEST_PATH
  DEPLOYMENT_OPERATOR
  DILIGENCE_ATTESTATION_VERIFIER
  DILIGENCE_COMPOSE_HASH
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3
  DILIGENCE_EVALUATOR_POLICY_SET_ROOT
  DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE
  DILIGENCE_GOVERNANCE_ACCEPTANCE_RECORD
  DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH
  DILIGENCE_GOVERNANCE_CONTROLLER
  DILIGENCE_QVL_RELEASE_POLICY_HASH
  DILIGENCE_RELEASE_PHASE
  DILIGENCE_RESULT_VERIFIER
  DILIGENCE_ROOM_ADDRESS
  DILIGENCE_RUNTIME_CODE_HASH
  DILIGENCE_TEE_IDENTITY
  EMAIL_ORACLE_AUTH_ADDRESS
  EMAIL_ORACLE_BOOT_INSTANCE_ID
  EMAIL_ORACLE_BOOT_MR_AGGREGATED
  EMAIL_ORACLE_BOOT_MR_SYSTEM
  EMAIL_ORACLE_BOOT_OS_IMAGE_HASH
  EMAIL_ORACLE_COMPOSE_HASH
  EMAIL_ORACLE_CONSUMER_APP_ID
  EMAIL_ORACLE_CONSUMER_COMPOSE_HASH
  EMAIL_ORACLE_DEVICE_ID
  EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH
  EMAIL_ORACLE_KMS_ADDRESS
  EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS
  EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH
  EMAIL_ORACLE_KMS_REGISTRATION_BLOCK
  EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH
  EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH
  EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH
  EMAIL_ORACLE_RELEASE_PHASE
  EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256
  EMAIL_ORACLE_RUNTIME_CODE_HASH
  EMAIL_ORACLE_UPGRADE_DELAY
  ETHERSCAN_API_KEY
  EXECUTION_POLICY_ANCHOR_ADDRESS
  EXECUTION_POLICY_ANCHOR_RELEASE_PHASE
  EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH
  EXECUTION_POLICY_ANCHOR_WRITER
  EXECUTION_POLICY_RELEASE_CORE_PATH
  FINAL_RELEASE_AUTHORITY_CORE_PATH
  FOUNDRY_BROADCAST
  FOUNDRY_CACHE_PATH
  FOUNDRY_KEYSTORE_ACCOUNT
  FOUNDRY_OUT
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256
  OPERATOR_POLICY_REVIEW_ENVELOPE_PATH
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256
  RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT
  RELEASE_CEREMONY_LEDGER_PATH
  RELEASE_CEREMONY_LOCK_ROOT
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH
  RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH
  RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH
  RELEASE_SHA
  ROYALTY_DISTRIBUTOR_ADDRESS
  ROYALTY_DISTRIBUTOR_RUNTIME_CODE_HASH
  ROYALTY_QVL_VERIFIER
  ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH
  ROYALTY_RELEASE_OPERATION
  ROYALTY_RELEASE_PHASE_PLAN_PATH
  ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_PATH
  ROYALTY_RELEASE_PRIOR_BROADCAST_RECEIPT_PATH
  ROYALTY_RELEASE_REVIEWER_CURRENT_STATUS_PATH
  ROYALTY_RELEASE_REVIEWER_GENESIS_ACCEPTANCE_PATH
  ROYALTY_RELEASE_REVIEWER_GENESIS_PATH
  ROYALTY_RELEASE_REVIEWER_STATUS_HISTORY_PATH
  ROYALTY_SETTLEMENT_VERIFIER
  TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256
  TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT
  TINKER_ENCUMBRANCE_ADDRESS
  TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI
  TINKER_ENCUMBRANCE_MAX_SPEND_WEI
  TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT
  TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH
  TINKER_ENCUMBRANCE_RELEASE_MANAGER
  TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI
  TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI
  TINKER_ENCUMBRANCE_RELEASE_PHASE
  TINKER_ENCUMBRANCE_RUNTIME_CODE_HASH
  TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT
  VERIFY
)
readonly DNAI_ALLOWED_DEPLOYMENT_DOTENV_NAMES

dnai_is_forbidden_raw_signer_name() {
  local candidate="$1"
  local raw_signer_name
  local matched=false
  local nocasematch_was_set=false

  if dnai_is_ignored_purpose_scoped_cvm_name "$candidate"; then
    return 1
  fi
  if shopt -q nocasematch; then
    nocasematch_was_set=true
  else
    shopt -s nocasematch
  fi
  if [[ "$candidate" == *PRIVATE_KEY* ]] || [[ "$candidate" == *MNEMONIC* ]]; then
    matched=true
  fi
  for raw_signer_name in "${DNAI_FORBIDDEN_RAW_SIGNER_ENV_NAMES[@]}"; do
    if [ "$matched" = "true" ] || [[ "$candidate" == "$raw_signer_name" ]]; then
      matched=true
      break
    fi
  done
  if [ "$nocasematch_was_set" != "true" ]; then
    shopt -u nocasematch
  fi
  [ "$matched" = "true" ]
}

dnai_reject_raw_signer_name() {
  local raw_signer_name="$1"
  echo "$raw_signer_name is forbidden for Base Sepolia release operations; use only the encrypted Foundry account dev." >&2
  return 1
}

dnai_reject_raw_signer_environment() {
  local exported_names=""
  local environment_name=""
  local raw_signer_name

  # Catch non-exported canonical variables as well as exported spellings.
  for raw_signer_name in "${DNAI_FORBIDDEN_RAW_SIGNER_ENV_NAMES[@]}"; do
    if [ "${!raw_signer_name+x}" = "x" ]; then
      dnai_reject_raw_signer_name "$raw_signer_name"
      return 1
    fi
  done

  # Prefix invocation variables are exported. Bash's builtin enumeration emits
  # names only (including retained BASH_FUNC_* encodings under -p), so case
  # variants fail closed without copying or printing any environment value.
  exported_names="$(builtin compgen -e)" || {
    echo "Exported environment names could not be enumerated safely." >&2
    return 1
  }
  while IFS= read -r environment_name; do
    if dnai_is_forbidden_raw_signer_name "$environment_name"; then
      dnai_reject_raw_signer_name "$environment_name"
      return 1
    fi
  done <<< "$exported_names"
}

dnai_is_allowed_deployment_dotenv_name() {
  local candidate="$1"
  local allowed_name
  for allowed_name in "${DNAI_ALLOWED_DEPLOYMENT_DOTENV_NAMES[@]}"; do
    if [ "$candidate" = "$allowed_name" ]; then
      return 0
    fi
  done
  return 1
}

dnai_is_ignored_purpose_scoped_cvm_name() {
  case "$1" in
    TINKER_ARENA_CANDIDATE_INGRESS_PRIVATE_KEY_HEX|TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

dnai_is_forbidden_shell_control_name() {
  case "$1" in
    BASH_ENV|ENV|SHELLOPTS|BASHOPTS|BASH_XTRACEFD|PS4|CDPATH|GLOBIGNORE|IFS|PATH|LD_*|DYLD_*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

dnai_read_owned_file_metadata() {
  local path="$1"
  local metadata=""

  metadata="$(/usr/bin/stat -f '%u:%l:%Lp' -- "$path" 2>/dev/null || true)"
  if [[ ! "$metadata" =~ ^[0-9]+:[0-9]+:[0-7]+$ ]]; then
    metadata="$(/usr/bin/stat -c '%u:%h:%a' -- "$path" 2>/dev/null || true)"
  fi
  if [[ ! "$metadata" =~ ^[0-9]+:[0-9]+:[0-7]+$ ]]; then
    return 1
  fi
  printf '%s' "$metadata"
}

dnai_require_owned_single_link_data_file() {
  local path="$1"
  local label="$2"
  local metadata
  local owner
  local links
  local mode

  if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -r "$path" ]; then
    echo "$label must be a readable, non-symlink regular file." >&2
    return 1
  fi
  metadata="$(dnai_read_owned_file_metadata "$path")" || {
    echo "$label metadata could not be verified." >&2
    return 1
  }
  IFS=: read -r owner links mode <<< "$metadata"
  if [ "$owner" != "$EUID" ] || [ "$links" != "1" ] || [ "$mode" != "600" ]; then
    echo "$label must be owned by the invoking user, have one link, and have exact mode 0600." >&2
    return 1
  fi
}

dnai_load_keystore_deployment_dotenv() {
  local LC_ALL=C
  local dotenv_path="$1"
  local line=""
  local content=""
  local name=""
  local value=""
  local seen_names=$'\n'
  local line_number=0
  local index=0
  local allowed=false
  local errexit_was_set=false
  local od_status=0
  local grep_status=0
  local -a pipeline_status=()
  local -a dotenv_names=()
  local -a dotenv_values=()

  # These belong to CVM ingress custody, not Foundry. Never reclassify them as
  # signer aliases, and never forward caller/file values into release tools.
  unset TINKER_ARENA_CANDIDATE_INGRESS_PRIVATE_KEY_HEX
  unset TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX

  if [ -L "$dotenv_path" ]; then
    echo ".env must not be a symbolic link, including a dangling link." >&2
    return 1
  fi
  if [ ! -e "$dotenv_path" ]; then
    return 0
  fi
  dnai_require_owned_single_link_data_file "$dotenv_path" ".env" || return 1

  # Bash strings cannot represent NUL. Detect it on raw bytes before parsing;
  # the tools are absolute paths and neither command prints file content. Both
  # probe statuses are checked so an I/O/tool failure cannot mean "no NUL."
  case $- in *e*) errexit_was_set=true ;; esac
  set +e
  /usr/bin/env -i LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/od -An -tx1 -- "$dotenv_path" \
    | /usr/bin/env -i LC_ALL=C PATH=/usr/bin:/bin \
      /usr/bin/grep -E '(^|[[:space:]])00([[:space:]]|$)' >/dev/null
  pipeline_status=("${PIPESTATUS[@]}")
  od_status=${pipeline_status[0]}
  grep_status=${pipeline_status[1]}
  if [ "$errexit_was_set" = "true" ]; then
    set -e
  fi
  if [ "$od_status" -ne 0 ] || [ "$grep_status" -gt 1 ]; then
    echo ".env raw-byte validation could not be completed safely." >&2
    return 1
  fi
  if [ "$grep_status" -eq 0 ]; then
    echo ".env contains a NUL byte and is not a supported data-only dotenv file." >&2
    return 1
  fi

  # Parse the whole file before assigning anything. Only blank lines, whole-
  # line comments, and canonical NAME=value records are accepted. The right-
  # hand side is inert literal data: nothing is evaluated or sourced as shell.
  while IFS= read -r line || [ -n "$line" ]; do
    line_number=$((line_number + 1))
    if [[ "$line" == *$'\r'* ]]; then
      echo ".env line $line_number contains a carriage return." >&2
      return 1
    fi

    content="$line"
    while :; do
      case "$content" in
        ' '*) content="${content#?}" ;;
        $'\t'*) content="${content#?}" ;;
        *) break ;;
      esac
    done
    if [ -z "$content" ] || [[ "$content" == \#* ]]; then
      continue
    fi

    case "$line" in
      *=*)
        name="${line%%=*}"
        value="${line#*=}"
        ;;
      *)
        echo ".env line $line_number is not a canonical NAME=value record." >&2
        return 1
        ;;
    esac
    if [[ ! "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo ".env line $line_number has an invalid variable name." >&2
      return 1
    fi
    if dnai_is_forbidden_raw_signer_name "$name"; then
      dnai_reject_raw_signer_name "$name"
      return 1
    fi
    if dnai_is_forbidden_shell_control_name "$name"; then
      echo "$name is forbidden in the data-only deployment .env." >&2
      return 1
    fi
    allowed=false
    if dnai_is_allowed_deployment_dotenv_name "$name"; then
      allowed=true
    elif dnai_is_ignored_purpose_scoped_cvm_name "$name"; then
      allowed=false
    elif [ "${!name+x}" = "x" ]; then
      echo "$name is not an approved deployment .env input and would overwrite wrapper state." >&2
      return 1
    fi
    case "$seen_names" in
      *$'\n'"$name"$'\n'*)
        echo ".env repeats variable $name; duplicate records are forbidden." >&2
        return 1
        ;;
    esac
    seen_names="${seen_names}${name}"$'\n'
    if [ "$allowed" = "true" ]; then
      dotenv_names[${#dotenv_names[@]}]="$name"
      dotenv_values[${#dotenv_values[@]}]="$value"
    fi
  done < "$dotenv_path"

  while [ "$index" -lt "${#dotenv_names[@]}" ]; do
    printf -v "${dotenv_names[$index]}" '%s' "${dotenv_values[$index]}"
    export "${dotenv_names[$index]}"
    index=$((index + 1))
  done
  if [ "$DNAI_KEYSTORE_CALLER_DEPLOYMENT_MANIFEST_PATH_PRESENT" = "x" ]; then
    DEPLOYMENT_MANIFEST_PATH="$DNAI_KEYSTORE_CALLER_DEPLOYMENT_MANIFEST_PATH_VALUE"
    export DEPLOYMENT_MANIFEST_PATH
  fi
}

dnai_validate_deployment_switch() {
  local name="$1"
  local value="$2"
  if [ "$value" != "true" ] && [ "$value" != "false" ]; then
    echo "$name must be true or false." >&2
    return 1
  fi
}

dnai_finalize_keystore_deployment_environment() {
  local switch_name

  # Recheck after data-only dotenv loading before validating switches so raw
  # signer material remains the first reported post-file safety violation.
  dnai_reject_raw_signer_environment || return 1

  for switch_name in "$@"; do
    case "$switch_name" in
      BROADCAST)
        if [ "$DNAI_KEYSTORE_CALLER_BROADCAST_PRESENT" = "x" ]; then
          BROADCAST="$DNAI_KEYSTORE_CALLER_BROADCAST_VALUE"
        elif [ "${BROADCAST+x}" != "x" ]; then
          BROADCAST=false
        fi
        dnai_validate_deployment_switch BROADCAST "$BROADCAST" || return 1
        ;;
      VERIFY)
        if [ "$DNAI_KEYSTORE_CALLER_VERIFY_PRESENT" = "x" ]; then
          VERIFY="$DNAI_KEYSTORE_CALLER_VERIFY_VALUE"
        elif [ "${VERIFY+x}" != "x" ]; then
          VERIFY=false
        fi
        dnai_validate_deployment_switch VERIFY "$VERIFY" || return 1
        ;;
      *)
        echo "Unsupported keystore deployment switch: $switch_name" >&2
        return 1
        ;;
    esac
  done
}

readonly -f \
  dnai_is_forbidden_raw_signer_name \
  dnai_reject_raw_signer_name \
  dnai_reject_raw_signer_environment \
  dnai_is_allowed_deployment_dotenv_name \
  dnai_is_ignored_purpose_scoped_cvm_name \
  dnai_is_forbidden_shell_control_name \
  dnai_read_owned_file_metadata \
  dnai_require_owned_single_link_data_file \
  dnai_load_keystore_deployment_dotenv \
  dnai_validate_deployment_switch \
  dnai_finalize_keystore_deployment_environment

# A caller-supplied raw key must be rejected before dotenv parsing can erase,
# rewrite, or otherwise observe it.
dnai_reject_raw_signer_environment
