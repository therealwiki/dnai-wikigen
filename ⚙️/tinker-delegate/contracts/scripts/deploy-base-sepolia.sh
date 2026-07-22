#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
WORKING_CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
CONTRACTS_DIR="$WORKING_CONTRACTS_DIR"
MANIFEST_PATH=""
MANIFEST_FILTER=""
CHAIN_ID=84532
ACCOUNT=dev
MIN_EMAIL_ORACLE_UPGRADE_DELAY=172800
MAX_EMAIL_ORACLE_UPGRADE_DELAY=31536000
MAX_COMPUTE_VAULT_DEVELOPER_FEE_BPS=2000
MAX_TINKER_POLICY_UNITS_PER_OPERATION=10000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
AUTHORITY_COMMITMENT_READ_PROOF=primary_and_secondary_rpc_exact_getter_match_at_deployment_block
DEPLOYMENT_INTENT_RECEIPT=""
DEPLOYMENT_REVIEW_RECEIPT=""
DEPLOYMENT_REVIEW_EVIDENCE_SHA256=""
REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256=""
DEPLOYMENT_INTENT_SHA256_BYTES32=""
REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32=""
DEPLOYMENT_RECEIPTS='{}'
BROADCAST_TRANSACTIONS='[]'
BROADCAST_TRANSACTIONS_SHA256=""
BROADCAST_STARTED=false
BROADCAST_VALIDATED=false
BROADCAST_JOURNAL_PATH=""
RELEASE_WORKSPACE=""
RELEASE_WORKTREE=""
RUN_PATH=""
VERIFICATION_RECEIPT_PATH=""
tmp_manifest=""
seed_manifest=""
verification_manifest=""

cleanup() {
  local exit_status=$?
  if [ "$BROADCAST_STARTED" = "true" ] \
    && [ "$BROADCAST_VALIDATED" != "true" ] \
    && [ -n "$BROADCAST_JOURNAL_PATH" ] \
    && declare -F write_broadcast_journal_status >/dev/null 2>&1; then
    write_broadcast_journal_status "abandoned_after_broadcast_validation_failure" \
      "Fresh-suite broadcast was attempted, but exact post-broadcast validation or ledger persistence did not complete." \
      || true
  fi
  if [ -n "$tmp_manifest" ]; then
    rm -f -- "$tmp_manifest"
  fi
  if [ -n "$seed_manifest" ]; then
    rm -f -- "$seed_manifest"
  fi
  if [ -n "$verification_manifest" ]; then
    rm -f -- "$verification_manifest"
  fi
  if [ -n "$RELEASE_WORKTREE" ] && [ -d "$RELEASE_WORKTREE" ]; then
    git -C "$ROOT_DIR" worktree remove --force "$RELEASE_WORKTREE" >/dev/null 2>&1 || true
  fi
  if [ -n "$RELEASE_WORKSPACE" ]; then
    rm -rf -- "$RELEASE_WORKSPACE"
  fi
  return "$exit_status"
}

trap cleanup EXIT

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; no deployment identity or trust root is inferred." >&2
    exit 1
  fi
}

validate_address() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]] || [[ "$value" =~ ^0x0{40}$ ]]; then
    echo "$name must be a nonzero Ethereum address." >&2
    exit 1
  fi
}

validate_bytes32() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] || [[ "$value" =~ ^0x0{64}$ ]]; then
    echo "$name must be a nonzero bytes32 hex value." >&2
    exit 1
  fi
}

validate_uint() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an unsigned integer." >&2
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
    echo "TINKER_ENCUMBRANCE_MAX_SPEND_WEI must not exceed TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI." >&2
    exit 1
  fi
}

validate_uint_range() {
  local name="$1"
  local value="$2"
  local minimum="$3"
  local maximum="$4"
  validate_uint "$name" "$value"
  if ! jq -en \
    --arg value "$value" \
    --arg minimum "$minimum" \
    --arg maximum "$maximum" \
    '($value | tonumber) >= ($minimum | tonumber)
      and ($value | tonumber) <= ($maximum | tonumber)' >/dev/null; then
    echo "$name must be between $minimum and $maximum seconds." >&2
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

validate_sha256() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [[ "$value" =~ ^sha256:0{64}$ ]]; then
    echo "$name must be a nonzero lowercase sha256:<64-hex> digest." >&2
    exit 1
  fi
}

validate_release_sha() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9a-f]{40}$ ]]; then
    echo "$name must be the lowercase 40-hex reviewed Git commit." >&2
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
    throw new Error("invalid RPC endpoint");
  }
  const endpoint = new URL(value);
  if (endpoint.protocol !== "https:"
    || !endpoint.hostname
    || endpoint.username
    || endpoint.password
    || endpoint.hash) {
    throw new Error("invalid RPC endpoint");
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
    echo "Primary and secondary Base Sepolia RPC endpoints must be valid HTTPS URLs with distinct origins." >&2
    exit 1
  fi
}

normalize_address() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

normalize_hex_word() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

assert_address_equal() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [ "$(normalize_address "$expected")" != "$(normalize_address "$actual")" ]; then
    echo "$label mismatch: expected $expected, received $actual" >&2
    exit 1
  fi
}

assert_source_checkout_exact() {
  local stage="$1"
  local working_head
  local snapshot_head

  working_head="$(git -C "$ROOT_DIR" rev-parse HEAD | tr '[:upper:]' '[:lower:]')"
  if [ "$working_head" != "$RELEASE_SHA" ]; then
    echo "$stage source check failed: the working checkout moved away from RELEASE_SHA." >&2
    return 1
  fi
  if [ "$BROADCAST" = "true" ] \
    && [ -n "$(git -C "$ROOT_DIR" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
    echo "$stage source check failed: the working checkout is no longer clean." >&2
    return 1
  fi
  if [ -z "$RELEASE_WORKTREE" ] || [ ! -d "$RELEASE_WORKTREE" ]; then
    echo "$stage source check failed: the immutable release worktree is unavailable." >&2
    return 1
  fi
  snapshot_head="$(git -C "$RELEASE_WORKTREE" rev-parse HEAD | tr '[:upper:]' '[:lower:]')"
  if [ "$(git -C "$RELEASE_WORKTREE" rev-parse --abbrev-ref HEAD)" != "HEAD" ]; then
    echo "$stage source check failed: the immutable release worktree is not detached." >&2
    return 1
  fi
  if [ "$snapshot_head" != "$RELEASE_SHA" ] \
    || [ -n "$(git -C "$RELEASE_WORKTREE" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
    echo "$stage source check failed: the immutable release worktree changed." >&2
    return 1
  fi
}

assert_release_toolchain_exact() {
  local forge_output
  local cast_output
  local forge_config
  local expected_forge_version
  local expected_cast_version
  local expected_commit
  local expected_build_profile
  local expected_cast_executable_sha256
  local cast_path
  local canonical_cast_path
  local expected_solc_config
  local expected_compiler_version
  local expected_evm_version
  local expected_bytecode_hash

  expected_forge_version="$(jq -er '.release.toolchain.foundry.forgeVersion' "$DEPLOYMENT_INTENT_PATH")"
  expected_cast_version="$(jq -er '.release.toolchain.foundry.castVersion' "$DEPLOYMENT_INTENT_PATH")"
  expected_commit="$(jq -er '.release.toolchain.foundry.commitSha' "$DEPLOYMENT_INTENT_PATH")"
  expected_build_profile="$(jq -er '.release.toolchain.foundry.buildProfile' "$DEPLOYMENT_INTENT_PATH")"
  expected_cast_executable_sha256="$(jq -er '.release.toolchain.foundry.castExecutableSha256' "$DEPLOYMENT_INTENT_PATH")"
  expected_solc_config="$(jq -er '.release.toolchain.solidity.configuredVersion' "$DEPLOYMENT_INTENT_PATH")"
  expected_compiler_version="$(jq -er '.release.toolchain.solidity.compilerVersion' "$DEPLOYMENT_INTENT_PATH")"
  expected_evm_version="$(jq -er '.release.toolchain.solidity.evmVersion' "$DEPLOYMENT_INTENT_PATH")"
  expected_bytecode_hash="$(jq -er '.release.toolchain.solidity.bytecodeHash' "$DEPLOYMENT_INTENT_PATH")"

  forge_output="$(forge --version)"
  cast_output="$(cast --version)"
  cast_path="$(command -v cast)"
  canonical_cast_path="$(realpath "$cast_path")"
  if [ "$cast_path" != "$canonical_cast_path" ] \
    || [ "$(stat -f '%l' "$canonical_cast_path")" != "1" ] \
    || [ "$(shasum -a 256 "$canonical_cast_path" | awk '{print $1}')" != "$expected_cast_executable_sha256" ]; then
    echo "cast executable path/link/digest does not match the reviewed deployment-intent v6 toolchain." >&2
    return 1
  fi
  if [ "$(printf '%s\n' "$forge_output" | sed -n '1p')" != "forge Version: $expected_forge_version" ] \
    || [ "$(printf '%s\n' "$forge_output" | grep -c '^Commit SHA: ' || true)" != "1" ] \
    || [ "$(printf '%s\n' "$forge_output" | sed -n 's/^Commit SHA: //p')" != "$expected_commit" ] \
    || [ "$(printf '%s\n' "$forge_output" | sed -n 's/^Build Profile: //p')" != "$expected_build_profile" ]; then
    echo "forge binary identity does not match the reviewed deployment-intent v6 toolchain." >&2
    return 1
  fi
  if [ "$(printf '%s\n' "$cast_output" | sed -n '1p')" != "cast Version: $expected_cast_version" ] \
    || [ "$(printf '%s\n' "$cast_output" | grep -c '^Commit SHA: ' || true)" != "1" ] \
    || [ "$(printf '%s\n' "$cast_output" | sed -n 's/^Commit SHA: //p')" != "$expected_commit" ] \
    || [ "$(printf '%s\n' "$cast_output" | sed -n 's/^Build Profile: //p')" != "$expected_build_profile" ]; then
    echo "cast binary identity does not match the reviewed deployment-intent v6 toolchain." >&2
    return 1
  fi

  forge_config="$(forge config --json)"
  if ! jq -e \
    --arg solc "$expected_solc_config" \
    --arg evmVersion "$expected_evm_version" \
    --arg bytecodeHash "$expected_bytecode_hash" '
      .solc == $solc
      and .optimizer == true
      and .optimizer_runs == 200
      and .via_ir == true
      and .evm_version == $evmVersion
      and .bytecode_hash == $bytecodeHash
      and .cbor_metadata == true
      and .use_literal_content == false
      and .libraries == []
    ' <<<"$forge_config" >/dev/null; then
    echo "Foundry compilation settings do not match the reviewed deployment-intent v6 toolchain." >&2
    return 1
  fi

  # Retain the compiler identity for the artifact metadata check without
  # trusting an independently installed solc executable (Foundry owns solc).
  REVIEWED_SOLC_COMPILER_VERSION="$expected_compiler_version"
  REVIEWED_SOLC_EVM_VERSION="$expected_evm_version"
  REVIEWED_SOLC_BYTECODE_HASH="$expected_bytecode_hash"
}

assert_contract_build_metadata_exact() {
  local contract_name
  local metadata
  for contract_name in \
    DiligenceRoom \
    TinkerAccountEncumbrance \
    RoyaltyDistributor \
    ChallengeRegistry \
    ComputeCreditVault \
    EmailOracleAuth \
    ExecutionPolicyAnchor; do
    metadata="$(forge inspect "$contract_name" metadata)"
    if ! jq -e \
      --arg compiler "$REVIEWED_SOLC_COMPILER_VERSION" \
      --arg evmVersion "$REVIEWED_SOLC_EVM_VERSION" \
      --arg bytecodeHash "$REVIEWED_SOLC_BYTECODE_HASH" '
        .compiler.version == $compiler
        and .settings.optimizer == {enabled: true, runs: 200}
        and .settings.viaIR == true
        and .settings.evmVersion == $evmVersion
        and .settings.metadata == {bytecodeHash: $bytecodeHash}
        and .settings.libraries == {}
      ' <<<"$metadata" >/dev/null; then
      echo "$contract_name artifact metadata does not match the reviewed compiler identity and settings." >&2
      return 1
    fi
  done
}

durably_publish_json() {
  local source_path="$1"
  local output_path="$2"
  local publish_mode="$3"
  local file_mode="$4"
  local -a command=(
    node "$ROOT_DIR/scripts/durable-json-write.mjs"
    --source "$source_path"
    --out "$output_path"
    --publish-mode "$publish_mode"
    --file-mode "$file_mode"
  )
  if [ -n "${DEPLOYMENT_DURABILITY_FAULT_STAGE:-}" ]; then
    command+=(--fault-stage "$DEPLOYMENT_DURABILITY_FAULT_STAGE")
  fi
  "${command[@]}" >/dev/null
}

write_broadcast_journal_status() {
  local status="$1"
  local note="$2"
  local journal_dir
  local journal_tmp
  local recorded_at
  local artifact_sha256=""
  local artifact_file=""
  local publish_mode="replace"

  if [ -z "$BROADCAST_JOURNAL_PATH" ]; then
    return 1
  fi
  journal_dir="$(dirname "$BROADCAST_JOURNAL_PATH")"
  recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  journal_tmp="$(mktemp "$journal_dir/.fresh-suite-journal.tmp.XXXXXX")"
  if [ -n "$RUN_PATH" ] && [ -f "$RUN_PATH" ]; then
    if [ "$(wc -c < "$RUN_PATH" | tr -d '[:space:]')" -gt 2097152 ]; then
      rm -f -- "$journal_tmp"
      echo "Broadcast artifact exceeds the 2 MiB durable-journal evidence bound." >&2
      return 1
    fi
    jq empty "$RUN_PATH"
    artifact_file="$RUN_PATH"
    artifact_sha256="sha256:$(node -e '
      const fs = require("node:fs");
      const crypto = require("node:crypto");
      process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex"));
    ' "$RUN_PATH")"
  fi

  if [ -n "$artifact_file" ]; then
    jq -n \
      --slurpfile artifact "$artifact_file" \
      --arg status "$status" \
      --arg note "$note" \
      --arg recordedAt "$recorded_at" \
      --arg releaseSha "$RELEASE_SHA" \
      --arg deploymentIntentSha256 "$DEPLOYMENT_INTENT_SHA256" \
      --arg reviewerAuthorityGenesisAcceptanceSha256 "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256" \
      --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
      --arg reviewEvidenceSha256 "$DEPLOYMENT_REVIEW_EVIDENCE_SHA256" \
      --arg operator "$(normalize_address "$DEPLOYMENT_OPERATOR")" \
      --arg startingNonce "$operator_nonce" \
      --arg artifactSha256 "$artifact_sha256" \
      --arg broadcastTransactionsSha256 "$BROADCAST_TRANSACTIONS_SHA256" \
      --argjson broadcastTransactions "$BROADCAST_TRANSACTIONS" '
        {
          schema: "dnai.fresh-suite-broadcast-journal.v1",
          status: $status,
          truthStatus: "durable_broadcast_attempt_evidence_not_final_cvm_binding_or_release_authority",
          note: $note,
          recordedAt: $recordedAt,
          releaseSha: $releaseSha,
          deploymentIntentSha256: $deploymentIntentSha256,
          reviewerAuthorityGenesisAcceptanceSha256: $reviewerAuthorityGenesisAcceptanceSha256,
          deploymentReviewEnvelopeSha256: $reviewEnvelopeSha256,
          deploymentReviewEvidenceSha256: $reviewEvidenceSha256,
          chainId: 84532,
          operatorAddress: $operator,
          keystoreAccount: "dev",
          startingNonce: ($startingNonce | tonumber),
          broadcastArtifactSha256: $artifactSha256,
          broadcastTransactionsSha256:
            (if $broadcastTransactionsSha256 == "" then null else $broadcastTransactionsSha256 end),
          broadcastTransactions: $broadcastTransactions,
          broadcastArtifact: $artifact[0]
        }
      ' > "$journal_tmp"
  else
    jq -n \
      --arg status "$status" \
      --arg note "$note" \
      --arg recordedAt "$recorded_at" \
      --arg releaseSha "$RELEASE_SHA" \
      --arg deploymentIntentSha256 "$DEPLOYMENT_INTENT_SHA256" \
      --arg reviewerAuthorityGenesisAcceptanceSha256 "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256" \
      --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
      --arg reviewEvidenceSha256 "$DEPLOYMENT_REVIEW_EVIDENCE_SHA256" \
      --arg operator "$(normalize_address "$DEPLOYMENT_OPERATOR")" \
      --arg startingNonce "$operator_nonce" '
        {
          schema: "dnai.fresh-suite-broadcast-journal.v1",
          status: $status,
          truthStatus: "durable_broadcast_attempt_evidence_not_final_cvm_binding_or_release_authority",
          note: $note,
          recordedAt: $recordedAt,
          releaseSha: $releaseSha,
          deploymentIntentSha256: $deploymentIntentSha256,
          reviewerAuthorityGenesisAcceptanceSha256: $reviewerAuthorityGenesisAcceptanceSha256,
          deploymentReviewEnvelopeSha256: $reviewEnvelopeSha256,
          deploymentReviewEvidenceSha256: $reviewEvidenceSha256,
          chainId: 84532,
          operatorAddress: $operator,
          keystoreAccount: "dev",
          startingNonce: ($startingNonce | tonumber),
          broadcastArtifactSha256: null,
          broadcastTransactionsSha256: null,
          broadcastTransactions: [],
          broadcastArtifact: null
        }
      ' > "$journal_tmp"
  fi
  if ! jq empty "$journal_tmp" >/dev/null \
    || [ "$(wc -c < "$journal_tmp" | tr -d '[:space:]')" -gt 4194304 ]; then
    rm -f -- "$journal_tmp"
    echo "Broadcast journal candidate is incomplete, invalid, or exceeds 4 MiB." >&2
    return 1
  fi
  if [ ! -e "$BROADCAST_JOURNAL_PATH" ]; then
    publish_mode="create"
  fi
  if ! durably_publish_json "$journal_tmp" "$BROADCAST_JOURNAL_PATH" "$publish_mode" 0600; then
    rm -f -- "$journal_tmp"
    return 1
  fi
  rm -f -- "$journal_tmp"
}

initialize_broadcast_journal() {
  local journal_dir="${DEPLOYMENT_BROADCAST_JOURNAL_DIR:-$ROOT_DIR/deployments/.fresh-suite-broadcast-journal}"
  local random_suffix
  local stamp
  if [[ "$journal_dir" != /* ]] || [ -L "$journal_dir" ]; then
    echo "DEPLOYMENT_BROADCAST_JOURNAL_DIR must be an absolute non-symlink path." >&2
    return 1
  fi
  mkdir -p "$journal_dir"
  chmod 0700 "$journal_dir"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  random_suffix="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(12).toString("hex"))')"
  BROADCAST_JOURNAL_PATH="$journal_dir/${RELEASE_SHA:0:12}-${operator_nonce}-${stamp}-${random_suffix}.json"
  if [ -e "$BROADCAST_JOURNAL_PATH" ] || [ -L "$BROADCAST_JOURNAL_PATH" ]; then
    echo "Fresh-suite journal collision; refusing to approach the broadcast boundary." >&2
    return 1
  fi
  write_broadcast_journal_status \
    "pre_broadcast_checkpoint_recovery_chain_inspection_required" \
    "This checkpoint was durably written before command invocation. If recovery observes it after interruption, inspect the signer nonce and Base Sepolia transaction history before concluding whether remote mutation occurred."
}

require_absolute_authority_file() {
  local name="$1"
  local value="${!name:-}"
  require_env "$name"
  if [[ "$value" != /* ]] || [ ! -f "$value" ] || [ -L "$value" ] || [ ! -r "$value" ]; then
    echo "$name must be an absolute, readable, non-symlink regular file." >&2
    exit 1
  fi
}

assert_intent_string_equal() {
  local environment_name="$1"
  local intent_path="$2"
  local expected
  local actual="${!environment_name}"
  if ! expected="$(jq -er \
    --arg path "$intent_path" \
    'getpath($path | split(".")) | select(type == "string" and length > 0)' \
    "$DEPLOYMENT_INTENT_PATH")"; then
    echo "Deployment intent is missing required field $intent_path." >&2
    exit 1
  fi
  case "$environment_name" in
    DEPLOYMENT_OPERATOR|COMPUTE_VAULT_DEVELOPER|RELEASE_SHA|TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT)
      expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
      actual="$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')"
      ;;
  esac
  if [ "$actual" != "$expected" ]; then
    echo "$environment_name does not match deployment intent field $intent_path." >&2
    exit 1
  fi
}

assert_intent_number_equal() {
  local environment_name="$1"
  local intent_path="$2"
  local expected
  if ! expected="$(jq -er \
    --arg path "$intent_path" \
    'getpath($path | split(".")) | select(type == "number" and isfinite) | tostring' \
    "$DEPLOYMENT_INTENT_PATH")"; then
    echo "Deployment intent is missing required numeric field $intent_path." >&2
    exit 1
  fi
  if [ "${!environment_name}" != "$expected" ]; then
    echo "$environment_name does not match deployment intent field $intent_path." >&2
    exit 1
  fi
}

for required in forge cast jq git node; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required" >&2
    exit 1
  fi
done

if [ -n "${OPERATOR_POLICY_PACKET_PATH:-}" ] \
  || [ -n "${OPERATOR_POLICY_PACKET_SHA256:-}" ] \
  || [ -n "${OPERATOR_POLICY_PROJECTION_PATH:-}" ]; then
  echo "Legacy operator-policy packet and projection inputs are retired and rejected." >&2
  exit 1
fi
if [ -n "${FINAL_RELEASE_AUTHORITY_CORE_PATH:-}" ] \
  || [ -n "${OPERATOR_POLICY_FINAL_AUTHORITY_SHA256:-}" ]; then
  echo "Final-release authority cannot exist before fresh contract and CVM measurements; clear final-authority inputs." >&2
  exit 1
fi

require_env BASE_SEPOLIA_RPC_URL
require_env BASE_SEPOLIA_SECONDARY_RPC_URL
require_env DEPLOYMENT_INTENT_PATH
require_env DEPLOYMENT_INTENT_SHA256
require_env OPERATOR_POLICY_REVIEW_ENVELOPE_PATH
require_env OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256
require_env DEPLOYMENT_OPERATOR
require_env COMPUTE_VAULT_DEVELOPER
require_env COMPUTE_VAULT_DEVELOPER_FEE_BPS
require_env RELEASE_SHA
require_env TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT
require_env TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI
require_env TINKER_ENCUMBRANCE_MAX_SPEND_WEI
require_env EMAIL_ORACLE_UPGRADE_DELAY

require_absolute_authority_file DEPLOYMENT_INTENT_PATH
require_absolute_authority_file OPERATOR_POLICY_REVIEW_ENVELOPE_PATH
validate_sha256 DEPLOYMENT_INTENT_SHA256 "$DEPLOYMENT_INTENT_SHA256"
validate_sha256 OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"
validate_release_sha RELEASE_SHA "$RELEASE_SHA"

MANIFEST_PATH="${DEPLOYMENT_MANIFEST_PATH:-$ROOT_DIR/deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json}"
if [[ "$MANIFEST_PATH" != /* ]]; then
  echo "DEPLOYMENT_MANIFEST_PATH must be an absolute path when explicitly set." >&2
  exit 1
fi
if [ "$MANIFEST_PATH" = "$ROOT_DIR/deployments/base-sepolia.json" ]; then
  echo "The historical deployments/base-sepolia.json ledger is not a fresh deployment authority or writable output." >&2
  exit 1
fi
if [ -e "$MANIFEST_PATH" ] || [ -L "$MANIFEST_PATH" ]; then
  echo "Refusing to replace an existing fresh-suite manifest; choose a new immutable release-scoped output path." >&2
  exit 1
fi

if ! DEPLOYMENT_INTENT_RECEIPT="$(node \
  "$ROOT_DIR/scripts/operator-policy-packet.mjs" \
  check-intent \
  --in "$DEPLOYMENT_INTENT_PATH")"; then
  echo "Deployment-intent validation failed." >&2
  exit 1
fi
if [ "${#DEPLOYMENT_INTENT_RECEIPT}" -gt 8192 ] || ! jq -e \
  --arg intentSha "$DEPLOYMENT_INTENT_SHA256" \
  --arg releaseSha "$RELEASE_SHA" '
    keys == [
      "canonicalContractCount",
      "canonicalCvmCount",
      "chainId",
      "deploymentIntentSha256",
      "dynamicRuntimeAuthorityCount",
      "qvlNumericPolicyCount",
      "releaseSha",
      "reviewerAuthorityCurrentStatusEpoch",
      "reviewerAuthorityCurrentStatusSha256",
      "schema",
      "staticContractInputCount",
      "status",
      "truthStatus"
    ]
    and .schema == "dnai.deployment-intent-validation-receipt.v6"
    and .status == "valid"
    and .truthStatus == "intent_shape_and_bounds_validated_not_signer_control_deployment_or_tdx"
    and .deploymentIntentSha256 == $intentSha
    and .releaseSha == $releaseSha
    and .chainId == 84532
    and .canonicalContractCount == 7
    and .canonicalCvmCount == 7
    and .dynamicRuntimeAuthorityCount == 0
    and .qvlNumericPolicyCount == 5
    and .reviewerAuthorityCurrentStatusEpoch >= 1
    and .reviewerAuthorityCurrentStatusEpoch <= 4294967295
    and (.reviewerAuthorityCurrentStatusEpoch % 1) == 0
    and (.reviewerAuthorityCurrentStatusSha256 | test("^sha256:[0-9a-f]{64}$"))
    and .reviewerAuthorityCurrentStatusSha256 != "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    and .staticContractInputCount == 2
  ' <<<"$DEPLOYMENT_INTENT_RECEIPT" >/dev/null; then
  echo "Deployment-intent receipt does not match the reviewed digest, release, or exact schema." >&2
  exit 1
fi

if ! DEPLOYMENT_REVIEW_RECEIPT="$(node \
  "$ROOT_DIR/scripts/operator-policy-packet.mjs" \
  check-review \
  --subject "$DEPLOYMENT_INTENT_PATH" \
  --in "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH")"; then
  echo "Deployment-intent review-envelope validation failed." >&2
  exit 1
fi
if [ "${#DEPLOYMENT_REVIEW_RECEIPT}" -gt 8192 ] || ! jq -e \
  --arg intentSha "$DEPLOYMENT_INTENT_SHA256" \
  --arg reviewSha "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" '
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
    ]
    and .schema == "dnai.authority-review-envelope-validation-receipt.v1"
    and .status == "valid"
    and .truthStatus == "canonical_subject_binding_and_review_declarations_validated_not_signatures_key_control_deployment_or_tdx"
    and .subjectKind == "deployment_intent"
    and .subjectSemanticValidation == "deployment_intent_validated"
    and .subjectSha256 == $intentSha
    and .reviewEnvelopeSha256 == $reviewSha
    and (.reviewEvidenceSha256 | type == "string" and test("^sha256:[0-9a-f]{64}$") and . != "sha256:" + ("0" * 64))
    and .checkpoint == "before_any_contract_broadcast_or_cvm_deployment"
    and .actionScopeCount == 7
    and .reviewerDeclarationCount == 2
  ' <<<"$DEPLOYMENT_REVIEW_RECEIPT" >/dev/null; then
  echo "Deployment review receipt does not match the intent, envelope, or exact schema." >&2
  exit 1
fi
DEPLOYMENT_REVIEW_EVIDENCE_SHA256="$(jq -er '.reviewEvidenceSha256' <<<"$DEPLOYMENT_REVIEW_RECEIPT")"
REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256="$(jq -er \
  '.release.reviewerAuthorityGenesisAcceptanceSha256
    | select(type == "string")' \
  "$DEPLOYMENT_INTENT_PATH")"
validate_sha256 \
  REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256 \
  "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256"
DEPLOYMENT_INTENT_SHA256_BYTES32="0x${DEPLOYMENT_INTENT_SHA256#sha256:}"
REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32="0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256#sha256:}"
validate_bytes32 DEPLOYMENT_INTENT_SHA256_BYTES32 "$DEPLOYMENT_INTENT_SHA256_BYTES32"
validate_bytes32 \
  REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32 \
  "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32"

# These are the deployment-time fields cryptographically covered by the
# immutable intent. Post-deployment role and CVM identities remain absent from
# the intent by construction and are measured into the later final authority.
assert_intent_string_equal DEPLOYMENT_OPERATOR deploymentControl.operatorAddress
assert_intent_string_equal RELEASE_SHA release.releaseSha
assert_intent_string_equal COMPUTE_VAULT_DEVELOPER staticContractInputs.computeCreditVault.developer
assert_intent_string_equal TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT staticContractInputs.tinkerAccountEncumbrance.accountCommitment
assert_intent_number_equal COMPUTE_VAULT_DEVELOPER_FEE_BPS numericPolicy.contract.computeDeveloperFeeBps
assert_intent_number_equal EMAIL_ORACLE_UPGRADE_DELAY numericPolicy.contract.emailOracleUpgradeDelaySeconds
assert_intent_string_equal TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI numericPolicy.contract.tinkerMaxAddBalanceWei
assert_intent_string_equal TINKER_ENCUMBRANCE_MAX_SPEND_WEI numericPolicy.contract.tinkerMaxSpendWei

CURRENT_SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD | tr '[:upper:]' '[:lower:]')"
if [ "$CURRENT_SOURCE_COMMIT" != "$RELEASE_SHA" ]; then
  echo "RELEASE_SHA from the deployment intent does not equal the checked-out Git commit." >&2
  exit 1
fi

RPC_URL="$BASE_SEPOLIA_RPC_URL"
SECONDARY_RPC_URL="$BASE_SEPOLIA_SECONDARY_RPC_URL"
BROADCAST="${BROADCAST:-false}"
VERIFY="${VERIFY:-false}"

validate_rpc_authority_pair "$RPC_URL" "$SECONDARY_RPC_URL"

if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  echo "Fresh-suite deployment is restricted to the Foundry keystore account named dev." >&2
  exit 1
fi

validate_address DEPLOYMENT_OPERATOR "$DEPLOYMENT_OPERATOR"
validate_address COMPUTE_VAULT_DEVELOPER "$COMPUTE_VAULT_DEVELOPER"
if [ "$(normalize_address "$DEPLOYMENT_OPERATOR")" = "$(normalize_address "$COMPUTE_VAULT_DEVELOPER")" ]; then
  echo "DEPLOYMENT_OPERATOR and compute developer must be separate roles." >&2
  exit 1
fi
validate_uint COMPUTE_VAULT_DEVELOPER_FEE_BPS "$COMPUTE_VAULT_DEVELOPER_FEE_BPS"
if ! jq -en \
  --arg value "$COMPUTE_VAULT_DEVELOPER_FEE_BPS" \
  --arg maximum "$MAX_COMPUTE_VAULT_DEVELOPER_FEE_BPS" \
  '($value | tonumber) <= ($maximum | tonumber)' >/dev/null; then
  echo "COMPUTE_VAULT_DEVELOPER_FEE_BPS must not exceed $MAX_COMPUTE_VAULT_DEVELOPER_FEE_BPS." >&2
  exit 1
fi
validate_bytes32 TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT"
validate_uint TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI"
validate_uint TINKER_ENCUMBRANCE_MAX_SPEND_WEI "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI"
validate_tinker_policy_caps \
  "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" \
  "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI"
validate_uint_range \
  EMAIL_ORACLE_UPGRADE_DELAY \
  "$EMAIL_ORACLE_UPGRADE_DELAY" \
  "$MIN_EMAIL_ORACLE_UPGRADE_DELAY" \
  "$MAX_EMAIL_ORACLE_UPGRADE_DELAY"
validate_bool BROADCAST "$BROADCAST"
validate_bool VERIFY "$VERIFY"

if [ "$VERIFY" = "true" ]; then
  require_env ETHERSCAN_API_KEY
  VERIFICATION_RECEIPT_PATH="${MANIFEST_PATH%.json}.basescan-submission.json"
  if [ -e "$VERIFICATION_RECEIPT_PATH" ] || [ -L "$VERIFICATION_RECEIPT_PATH" ]; then
    echo "Refusing to replace an existing BaseScan submission receipt." >&2
    exit 1
  fi
fi

if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
  echo "Foundry keystore account dev was not found. Use /cast-wallet to import it first." >&2
  exit 1
fi

export DEPLOYMENT_OPERATOR
export COMPUTE_VAULT_DEVELOPER
export COMPUTE_VAULT_DEVELOPER_FEE_BPS
export TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT
export TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI
export TINKER_ENCUMBRANCE_MAX_SPEND_WEI
export EMAIL_ORACLE_UPGRADE_DELAY
export DEPLOYMENT_INTENT_SHA256_BYTES32
export REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32

live_chain_id="$(cast chain-id --rpc-url "$RPC_URL")"
if [ "$live_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing to deploy: RPC reports chainId $live_chain_id, expected Base Sepolia $CHAIN_ID." >&2
  exit 1
fi
secondary_chain_id="$(cast chain-id --rpc-url "$SECONDARY_RPC_URL")"
if [ "$secondary_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing to deploy: secondary RPC reports chainId $secondary_chain_id, expected Base Sepolia $CHAIN_ID." >&2
  exit 1
fi

operator_balance_wei="$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$RPC_URL")"
operator_balance="$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$RPC_URL" --ether)"
operator_nonce="$(cast nonce "$DEPLOYMENT_OPERATOR" --rpc-url "$RPC_URL")"

if [ "$BROADCAST" = "true" ]; then
  if [ "$operator_balance_wei" = "0" ]; then
    echo "DEPLOYMENT_OPERATOR has no Base Sepolia ETH for deployment gas." >&2
    exit 1
  fi
  if [ -n "$(git -C "$ROOT_DIR" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" ]; then
    echo "Refusing to broadcast from a dirty source tree; commit the exact reviewed suite first." >&2
    exit 1
  fi
fi

if ! git -C "$ROOT_DIR" cat-file -e "${RELEASE_SHA}^{commit}"; then
  echo "RELEASE_SHA does not identify a commit in the local reviewed repository." >&2
  exit 1
fi
RELEASE_WORKSPACE="$(mktemp -d "${TMPDIR:-/tmp}/dnai-fresh-suite-release.XXXXXX")"
RELEASE_WORKTREE="$RELEASE_WORKSPACE/repository"
if ! git -C "$ROOT_DIR" worktree add --detach --quiet "$RELEASE_WORKTREE" "$RELEASE_SHA"; then
  echo "The immutable RELEASE_SHA worktree could not be created." >&2
  exit 1
fi
CONTRACTS_DIR="$RELEASE_WORKTREE/⚙️/tinker-delegate/contracts"
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/merge-base-sepolia-suite-manifest.jq"
if [ ! -f "$CONTRACTS_DIR/script/DeployFreshSuite.s.sol" ] || [ ! -f "$MANIFEST_FILTER" ]; then
  echo "RELEASE_SHA does not contain the canonical fresh-suite source and manifest projector." >&2
  exit 1
fi
export FOUNDRY_OUT="$RELEASE_WORKSPACE/foundry/out"
export FOUNDRY_CACHE_PATH="$RELEASE_WORKSPACE/foundry/cache"
export FOUNDRY_BROADCAST="$RELEASE_WORKSPACE/foundry/broadcast"
export FOUNDRY_PROFILE=default
mkdir -p "$FOUNDRY_OUT" "$FOUNDRY_CACHE_PATH" "$FOUNDRY_BROADCAST"
assert_source_checkout_exact "pre-compilation"

echo "== Base Sepolia fresh-suite preflight =="
echo "RPC source:          BASE_SEPOLIA_RPC_URL (value not printed)"
echo "Chain ID:            $live_chain_id"
echo "Keystore account:    dev"
echo "Operator:            $DEPLOYMENT_OPERATOR"
echo "Result verifier:     unset until the post-deploy timelocked diligence ceremony"
echo "Compute developer:   $COMPUTE_VAULT_DEVELOPER"
echo "Metering binding:    unset until the post-deploy timelocked QVL ceremony"
echo "Compute fee:         $COMPUTE_VAULT_DEVELOPER_FEE_BPS bps (frozen at deployment)"
echo "Tinker policy units: add=$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI spend=$TINKER_ENCUMBRANCE_MAX_SPEND_WEI (per operation; not ETH or cumulative)"
echo "Operator balance:    $operator_balance"
echo "Operator nonce:      $operator_nonce"
echo "Oracle upgrade delay: $EMAIL_ORACLE_UPGRADE_DELAY seconds"
echo "Deployment intent:    $DEPLOYMENT_INTENT_SHA256"
echo "Signed reviewer genesis acceptance: $REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256"
echo "Deployment review:    $OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"
echo "Broadcast:           $BROADCAST"
echo "Verify on BaseScan:  $VERIFY"
echo "Manifest:            $MANIFEST_PATH"
echo "Release snapshot:    $RELEASE_SHA (detached immutable worktree)"

cd "$CONTRACTS_DIR"
assert_release_toolchain_exact

echo
echo "== Build and tests =="
forge build --sizes
assert_contract_build_metadata_exact
forge test --threads 1

echo
echo "== Dry run =="
forge script script/DeployFreshSuite.s.sol \
  --rpc-url "$RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

if [ "$BROADCAST" != "true" ]; then
  echo
  echo "Dry run complete. No chain or manifest state changed."
  echo "Set BROADCAST=true only after reviewing all explicit trust-root inputs."
  exit 0
fi

echo
echo "== Keystore signer check =="
unlocked_signer="$(cast wallet address --account dev)"
assert_address_equal "dev keystore signer" "$DEPLOYMENT_OPERATOR" "$unlocked_signer"
assert_source_checkout_exact "immediate pre-broadcast"
assert_release_toolchain_exact
assert_contract_build_metadata_exact
pre_broadcast_operator_nonce="$(cast nonce "$DEPLOYMENT_OPERATOR" --rpc-url "$RPC_URL")"
if [ "$(normalize_quantity "reviewed dry-run operator nonce" "$operator_nonce")" \
  != "$(normalize_quantity "immediate pre-broadcast operator nonce" "$pre_broadcast_operator_nonce")" ]; then
  echo "Operator nonce changed after the reviewed dry run; refusing to enter the indeterminate broadcast boundary." >&2
  exit 1
fi

echo
echo "== Broadcast reviewed-scope suite =="
initialize_broadcast_journal
BROADCAST_STARTED=true
set +e
forge script script/DeployFreshSuite.s.sol:DeployFreshSuiteScript \
  --rpc-url "$RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --account dev \
  --broadcast \
  --slow
forge_broadcast_status=$?
set -e

RUN_PATH="$FOUNDRY_BROADCAST/DeployFreshSuite.s.sol/$CHAIN_ID/run-latest.json"
if [ ! -f "$RUN_PATH" ]; then
  write_broadcast_journal_status \
    "abandoned_after_broadcast_artifact_missing" \
    "The keystore broadcast command returned without a bounded Foundry broadcast artifact." || true
  echo "Broadcast artifact not found after keystore invocation: $RUN_PATH" >&2
  exit 1
fi
write_broadcast_journal_status \
  "broadcast_complete_pending_validation" \
  "Foundry wrote a broadcast artifact; exact mined input, receipt, order, and source validation remain pending."
if [ "$forge_broadcast_status" -ne 0 ]; then
  echo "Foundry reported broadcast failure; the durable journal preserves the available artifact." >&2
  exit "$forge_broadcast_status"
fi
assert_source_checkout_exact "immediate post-broadcast"

if ! jq -e '
  (.transactions | type == "array" and length == 13)
  and ([.transactions[] | {contractName, transactionType, function}] == [
    {contractName:"DiligenceRoom",transactionType:"CREATE",function:null},
    {contractName:"DiligenceRoom",transactionType:"CALL",function:"freezeFeeBps()"},
    {contractName:"DiligenceRoom",transactionType:"CALL",function:"enableComputeSettlementPolicy()"},
    {contractName:"DiligenceRoom",transactionType:"CALL",function:"setComposeApprovalRequired(bool)"},
    {contractName:"DiligenceRoom",transactionType:"CALL",function:"setTeeIdentityApprovalRequired(bool)"},
    {contractName:"DiligenceRoom",transactionType:"CALL",function:"freezeApprovalRequirements()"},
    {contractName:"TinkerAccountEncumbrance",transactionType:"CREATE",function:null},
    {contractName:"RoyaltyDistributor",transactionType:"CREATE",function:null},
    {contractName:"ChallengeRegistry",transactionType:"CREATE",function:null},
    {contractName:"ComputeCreditVault",transactionType:"CREATE",function:null},
    {contractName:"ComputeCreditVault",transactionType:"CALL",function:"freezeDeveloperFee()"},
    {contractName:"EmailOracleAuth",transactionType:"CREATE",function:null},
    {contractName:"ExecutionPolicyAnchor",transactionType:"CREATE",function:null}
  ])
  and all(.transactions[];
    (.hash | type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    and (.transaction | type == "object")
    and (.transaction.from | type == "string" and test("^0x[0-9a-fA-F]{40}$"))
    and (.transaction.input | type == "string" and test("^0x([0-9a-fA-F]{2})+$"))
    and (.transaction.nonce | (type == "string" or type == "number")))
  )
' "$RUN_PATH" >/dev/null; then
  echo "Broadcast artifact must contain the exact ordered 13-transaction fresh-suite plan." >&2
  exit 1
fi

artifact_contract_address() {
  local index="$1"
  local expected_name="$2"
  jq -er \
    --argjson index "$index" \
    --arg name "$expected_name" '
      .transactions[$index]
      | select(.transactionType == "CREATE" and .contractName == $name)
      | .contractAddress
      | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))
      | ascii_downcase
    ' "$RUN_PATH"
}

artifact_transaction_hash() {
  local index="$1"
  jq -er --argjson index "$index" '
    .transactions[$index].hash
    | select(type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    | ascii_downcase
  ' "$RUN_PATH"
}

normalize_quantity() {
  local label="$1"
  local raw="$2"
  local normalized
  if [[ "$raw" =~ ^0x[0-9a-fA-F]+$ ]]; then
    normalized="$(cast to-dec "$raw")"
  elif [[ "$raw" =~ ^[0-9]+$ ]]; then
    normalized="$raw"
  else
    echo "$label must be a hexadecimal or decimal unsigned quantity." >&2
    return 1
  fi
  validate_uint "$label" "$normalized"
  if ! jq -en --arg value "$normalized" '($value | tonumber) <= 9007199254740991' >/dev/null; then
    echo "$label exceeds the canonical safe-integer evidence range." >&2
    return 1
  fi
  printf '%s' "$normalized"
}

validate_transaction_input() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x([0-9a-f][0-9a-f])+$ ]]; then
    echo "$label must be nonempty canonical lowercase byte-aligned hex." >&2
    return 1
  fi
}

creation_input() {
  local contract_name="$1"
  local constructor_signature="$2"
  shift 2
  local creation_code
  local constructor_args="0x"
  local normalized
  creation_code="$(forge inspect "$contract_name" bytecode | tr '[:upper:]' '[:lower:]')"
  if [ -n "$constructor_signature" ]; then
    constructor_args="$(cast abi-encode "$constructor_signature" "$@" | tr '[:upper:]' '[:lower:]')"
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

DILIGENCE_ADDRESS="$(artifact_contract_address 0 DiligenceRoom)"
ENCUMBRANCE_ADDRESS="$(artifact_contract_address 6 TinkerAccountEncumbrance)"
ROYALTY_ADDRESS="$(artifact_contract_address 7 RoyaltyDistributor)"
CHALLENGE_ADDRESS="$(artifact_contract_address 8 ChallengeRegistry)"
COMPUTE_VAULT_ADDRESS="$(artifact_contract_address 9 ComputeCreditVault)"
EMAIL_ORACLE_ADDRESS="$(artifact_contract_address 11 EmailOracleAuth)"
EXECUTION_POLICY_ANCHOR_ADDRESS="$(artifact_contract_address 12 ExecutionPolicyAnchor)"
DILIGENCE_TX="$(artifact_transaction_hash 0)"
ENCUMBRANCE_TX="$(artifact_transaction_hash 6)"
ROYALTY_TX="$(artifact_transaction_hash 7)"
CHALLENGE_TX="$(artifact_transaction_hash 8)"
COMPUTE_VAULT_TX="$(artifact_transaction_hash 9)"
EMAIL_ORACLE_TX="$(artifact_transaction_hash 11)"
EXECUTION_POLICY_ANCHOR_TX="$(artifact_transaction_hash 12)"

for deployment_tx in \
  "$DILIGENCE_TX" \
  "$ENCUMBRANCE_TX" \
  "$ROYALTY_TX" \
  "$CHALLENGE_TX" \
  "$COMPUTE_VAULT_TX" \
  "$EMAIL_ORACLE_TX" \
  "$EXECUTION_POLICY_ANCHOR_TX"; do
  validate_bytes32 deployment_transaction "$deployment_tx"
done

for deployed_address in \
  "$DILIGENCE_ADDRESS" \
  "$ENCUMBRANCE_ADDRESS" \
  "$ROYALTY_ADDRESS" \
  "$CHALLENGE_ADDRESS" \
  "$COMPUTE_VAULT_ADDRESS" \
  "$EMAIL_ORACLE_ADDRESS" \
  "$EXECUTION_POLICY_ANCHOR_ADDRESS"; do
  validate_address deployed_contract "$deployed_address"
  if [ "$(cast code "$deployed_address" --rpc-url "$RPC_URL")" = "0x" ]; then
    echo "No runtime bytecode found at $deployed_address" >&2
    exit 1
  fi
done

# Reconstruct every exact CREATE and CALL input from the immutable release
# snapshot before consulting the mined transactions.
DILIGENCE_CREATE_INPUT="$(creation_input DiligenceRoom 'constructor(bool)' true)"
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
ROYALTY_CREATE_INPUT="$(creation_input RoyaltyDistributor '')"
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

EXPECTED_TRANSACTION_NONCE="$(normalize_quantity "operator starting nonce" "$operator_nonce")"

collect_broadcast_transaction() {
  local sequence="$1"
  local ledger_key="$2"
  local contract_name="$3"
  local transaction_type="$4"
  local function_signature="$5"
  local expected_input="$6"
  local contract_address="$7"
  local artifact_transaction
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
  artifact_transaction="$(jq -c --argjson sequence "$sequence" '.transactions[$sequence]' "$RUN_PATH")"
  transaction_hash="$(jq -er '.hash | ascii_downcase' <<<"$artifact_transaction")"
  artifact_from="$(jq -er '.transaction.from | ascii_downcase' <<<"$artifact_transaction")"
  artifact_to="$(jq -r 'if .transaction.to == null then "null" else (.transaction.to | ascii_downcase) end' <<<"$artifact_transaction")"
  artifact_input="$(jq -er '.transaction.input | ascii_downcase' <<<"$artifact_transaction")"
  artifact_nonce="$(normalize_quantity "$contract_name artifact nonce" "$(jq -r '.transaction.nonce' <<<"$artifact_transaction")")"
  assert_address_equal "$contract_name artifact sender" "$DEPLOYMENT_OPERATOR" "$artifact_from"
  if [ "$artifact_input" != "$expected_input" ]; then
    echo "$contract_name transaction $sequence artifact input differs from immutable RELEASE_SHA reconstruction." >&2
    return 1
  fi
  if [ "$artifact_nonce" != "$EXPECTED_TRANSACTION_NONCE" ]; then
    echo "$contract_name transaction $sequence artifact nonce is not the exact next operator nonce." >&2
    return 1
  fi
  if [ "$transaction_type" = "CREATE" ]; then
    if [ "$artifact_to" != "null" ]; then
      echo "$contract_name CREATE artifact unexpectedly has a target address." >&2
      return 1
    fi
  else
    assert_address_equal "$contract_name CALL artifact target" "$contract_address" "$artifact_to"
  fi

  tx_json="$(cast tx "$transaction_hash" --rpc-url "$RPC_URL" --json)" \
    || { echo "$contract_name mined transaction could not be read." >&2; return 1; }
  receipt_json="$(cast receipt "$transaction_hash" --rpc-url "$RPC_URL" --json)" \
    || { echo "$contract_name mined receipt could not be read." >&2; return 1; }
  if [ "${#tx_json}" -gt 1048576 ] || [ "${#receipt_json}" -gt 1048576 ]; then
    echo "$contract_name mined transaction evidence exceeds the 1 MiB per-record bound." >&2
    return 1
  fi
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
    echo "$contract_name transaction receipt does not prove success." >&2
    return 1
  fi
  if [ "$tx_hash" != "$transaction_hash" ] \
    || [ "$receipt_hash" != "$transaction_hash" ] \
    || [ "$tx_block" != "$receipt_block" ] \
    || [ "$tx_block_hash" != "$receipt_block_hash" ] \
    || [ "$tx_nonce" != "$EXPECTED_TRANSACTION_NONCE" ]; then
    echo "$contract_name transaction, receipt, artifact, block, or consecutive nonce linkage is inconsistent." >&2
    return 1
  fi
  assert_address_equal "$contract_name mined sender" "$DEPLOYMENT_OPERATOR" "$tx_from"
  assert_address_equal "$contract_name receipt sender" "$DEPLOYMENT_OPERATOR" "$receipt_from"
  validate_transaction_input "$contract_name mined transaction input" "$tx_input"
  if [ "$tx_input" != "$expected_input" ] || [ "$tx_input" != "$artifact_input" ]; then
    echo "$contract_name mined transaction input differs byte-for-byte from immutable RELEASE_SHA reconstruction." >&2
    return 1
  fi
  if [ "$transaction_type" = "CREATE" ]; then
    if [ "$tx_to" != "null" ]; then
      echo "$contract_name mined CREATE unexpectedly has a target address." >&2
      return 1
    fi
    receipt_contract_address="$(jq -er '
      .contractAddress
      | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))
      | ascii_downcase
    ' <<<"$receipt_json")"
    assert_address_equal "$contract_name receipt contract" "$contract_address" "$receipt_contract_address"
  else
    assert_address_equal "$contract_name mined CALL target" "$contract_address" "$tx_to"
    if ! jq -e '.contractAddress == null' <<<"$receipt_json" >/dev/null; then
      echo "$contract_name CALL receipt unexpectedly contains a created contract address." >&2
      return 1
    fi
    receipt_contract_address="null"
  fi
  input_sha256="$(transaction_input_sha256 "$tx_input")"

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
    ')"
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
      ')"
  fi
  EXPECTED_TRANSACTION_NONCE="$((EXPECTED_TRANSACTION_NONCE + 1))"
}

# Every one of the exact 13 mined transactions is confirmed before any
# deployment-manifest path is created or mutated. The EXIT trap retains the
# raw Foundry artifact plus any partial normalized evidence on any mismatch.
collect_broadcast_transaction 0 diligenceRoom DiligenceRoom CREATE 'constructor(bool)' "$DILIGENCE_CREATE_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 1 diligenceRoom DiligenceRoom CALL 'freezeFeeBps()' "$DILIGENCE_FREEZE_FEE_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 2 diligenceRoom DiligenceRoom CALL 'enableComputeSettlementPolicy()' "$DILIGENCE_ENABLE_SETTLEMENT_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 3 diligenceRoom DiligenceRoom CALL 'setComposeApprovalRequired(bool)' "$DILIGENCE_REQUIRE_COMPOSE_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 4 diligenceRoom DiligenceRoom CALL 'setTeeIdentityApprovalRequired(bool)' "$DILIGENCE_REQUIRE_IDENTITY_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 5 diligenceRoom DiligenceRoom CALL 'freezeApprovalRequirements()' "$DILIGENCE_FREEZE_APPROVAL_INPUT" "$DILIGENCE_ADDRESS"
collect_broadcast_transaction 6 tinkerAccountEncumbrance TinkerAccountEncumbrance CREATE 'constructor(address,bytes32,bytes32,uint256,uint256)' "$ENCUMBRANCE_CREATE_INPUT" "$ENCUMBRANCE_ADDRESS"
collect_broadcast_transaction 7 royaltyDistributor RoyaltyDistributor CREATE 'constructor()' "$ROYALTY_CREATE_INPUT" "$ROYALTY_ADDRESS"
collect_broadcast_transaction 8 challengeRegistry ChallengeRegistry CREATE 'constructor(address)' "$CHALLENGE_CREATE_INPUT" "$CHALLENGE_ADDRESS"
collect_broadcast_transaction 9 computeCreditVault ComputeCreditVault CREATE 'constructor(address,address,uint16)' "$COMPUTE_VAULT_CREATE_INPUT" "$COMPUTE_VAULT_ADDRESS"
collect_broadcast_transaction 10 computeCreditVault ComputeCreditVault CALL 'freezeDeveloperFee()' "$COMPUTE_VAULT_FREEZE_FEE_INPUT" "$COMPUTE_VAULT_ADDRESS"
collect_broadcast_transaction 11 emailOracleAuth EmailOracleAuth CREATE 'constructor(address,uint256,bool,bytes32,bytes32,bool)' "$EMAIL_ORACLE_CREATE_INPUT" "$EMAIL_ORACLE_ADDRESS"
collect_broadcast_transaction 12 executionPolicyAnchor ExecutionPolicyAnchor CREATE 'constructor(address,bytes32,bytes32)' "$EXECUTION_POLICY_ANCHOR_CREATE_INPUT" "$EXECUTION_POLICY_ANCHOR_ADDRESS"

if [ "$(jq -r 'length' <<<"$BROADCAST_TRANSACTIONS")" != "13" ] \
  || [ "$(jq -r 'length' <<<"$DEPLOYMENT_RECEIPTS")" != "7" ] \
  || [ "$(jq -r '[.[].transactionHash] | unique | length' <<<"$BROADCAST_TRANSACTIONS")" != "13" ]; then
  echo "Fresh deployment evidence must contain 13 distinct mined transactions and seven CREATE receipts." >&2
  exit 1
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
  ' "$ROOT_DIR/scripts/cvm-launch-intent-core.mjs")"
BROADCAST_TRANSACTIONS_SHA256="$(jq -er '.broadcast_transactions_sha256' <<<"$BROADCAST_EVIDENCE")"
validate_sha256 BROADCAST_TRANSACTIONS_SHA256 "$BROADCAST_TRANSACTIONS_SHA256"
if [ "$(jq -r '.broadcast_transactions | length' <<<"$BROADCAST_EVIDENCE")" != "13" ]; then
  echo "Canonical fresh deployment receipt projection rejected the ordered transaction evidence." >&2
  exit 1
fi
write_broadcast_journal_status \
  "broadcast_validated_pending_poststate_and_manifest" \
  "All 13 mined inputs, senders, targets, consecutive nonces, receipts, and CREATE addresses match the immutable release snapshot."
assert_source_checkout_exact "post-receipt-validation"

# Re-execute each exact creation bytecode locally against the Base Sepolia EVM
# with the release sender and constructor arguments. This resolves immutable
# references (including DiligenceRoom.developer = msg.sender) and proves the
# full deployed runtime, rather than treating non-empty bytecode as evidence.
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

  creation_code="$(forge inspect "$contract_name" bytecode)"
  if [ -n "$constructor_signature" ]; then
    expected_runtime="$(
      cast call \
        --from "$DEPLOYMENT_OPERATOR" \
        --rpc-url "$RPC_URL" \
        --create "$creation_code" \
        "$constructor_signature" \
        "$@"
    )"
  else
    expected_runtime="$(
      cast call \
        --from "$DEPLOYMENT_OPERATOR" \
        --rpc-url "$RPC_URL" \
        --create "$creation_code"
    )"
  fi

  deployed_runtime="$(cast code "$deployed_address" --rpc-url "$RPC_URL")"
  expected_hash="$(cast keccak "$expected_runtime")"
  deployed_hash="$(cast keccak "$deployed_runtime")"
  if [ "$deployed_hash" != "$expected_hash" ]; then
    echo "$contract_name runtime bytecode does not match this source, release sender, and constructor configuration." >&2
    return 1
  fi
  printf '%s' "$deployed_hash"
}

DILIGENCE_RUNTIME_CODE_HASH="$(
  assert_runtime_code \
    DiligenceRoom \
    "$DILIGENCE_ADDRESS" \
    'constructor(bool)' \
    true
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
  assert_runtime_code RoyaltyDistributor "$ROYALTY_ADDRESS" ''
)"
CHALLENGE_RUNTIME_CODE_HASH="$(
  assert_runtime_code \
    ChallengeRegistry \
    "$CHALLENGE_ADDRESS" \
    'constructor(address)' \
    "$DEPLOYMENT_OPERATOR"
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
echo "== On-chain trust-root reads =="
DILIGENCE_DEVELOPER="$(cast call "$DILIGENCE_ADDRESS" 'developer()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_PRODUCTION_RELEASE="$(cast call "$DILIGENCE_ADDRESS" 'productionRelease()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_DEAL_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'dealCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'resultVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_PENDING_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'pendingResultVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_PENDING_VERIFIER_AT="$(cast call "$DILIGENCE_ADDRESS" 'pendingResultVerifierActivatesAt()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_VERIFIER_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'resultVerifierFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_ATTESTATION_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'attestationVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_ATTESTATION_POLICY_HASH="$(cast call "$DILIGENCE_ADDRESS" 'attestationReleasePolicyHash()(bytes32)' --rpc-url "$RPC_URL")"
DILIGENCE_PENDING_ATTESTATION_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" 'pendingAttestationVerifier()(address)' --rpc-url "$RPC_URL")"
DILIGENCE_PENDING_ATTESTATION_POLICY_HASH="$(cast call "$DILIGENCE_ADDRESS" 'pendingAttestationReleasePolicyHash()(bytes32)' --rpc-url "$RPC_URL")"
DILIGENCE_PENDING_ATTESTATION_AT="$(cast call "$DILIGENCE_ADDRESS" 'pendingAttestationBindingActivatesAt()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_ATTESTATION_BINDING_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'attestationBindingFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_EVALUATOR_POLICIES_ABI="$(cast call "$DILIGENCE_ADDRESS" "$(cast calldata 'evaluatorPolicies()')" --rpc-url "$RPC_URL" | tr '[:upper:]' '[:lower:]')"
DILIGENCE_APPROVED_EVALUATOR_POLICY_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'approvedEvaluatorPolicyCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_PENDING_EVALUATOR_POLICY_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'pendingEvaluatorPolicyCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_EVALUATOR_POLICY_SET_ROOT="$(cast call "$DILIGENCE_ADDRESS" 'evaluatorPolicySetRoot()(bytes32)' --rpc-url "$RPC_URL")"
DILIGENCE_EVALUATOR_POLICY_SET_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'evaluatorPolicySetFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_REQUIRED_EVALUATOR_POLICY_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'REQUIRED_EVALUATOR_POLICY_COUNT()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_COMPOSE_REQUIRED="$(cast call "$DILIGENCE_ADDRESS" 'composeApprovalRequired()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_IDENTITY_REQUIRED="$(cast call "$DILIGENCE_ADDRESS" 'teeIdentityApprovalRequired()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_APPROVAL_REQUIREMENTS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'approvalRequirementsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_APPROVED_COMPOSE_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'approvedComposeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_APPROVED_TEE_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'approvedTeeIdentityCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_PENDING_COMPOSE_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'pendingComposeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_PENDING_TEE_COUNT="$(cast call "$DILIGENCE_ADDRESS" 'pendingTeeIdentityCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_COMPOSE_ADDITIONS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'composeAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_TEE_ADDITIONS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'teeIdentityAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_ZERO_COMPOSE_APPROVED="$(cast call "$DILIGENCE_ADDRESS" 'approvedComposeHashes(bytes32)(bool)' "$ZERO_BYTES32" --rpc-url "$RPC_URL")"
DILIGENCE_ZERO_TEE_COMPOSE="$(cast call "$DILIGENCE_ADDRESS" 'teeIdentityComposeHash(address)(bytes32)' "$(cast address-zero)" --rpc-url "$RPC_URL")"
DILIGENCE_FEE_BPS="$(cast call "$DILIGENCE_ADDRESS" 'feeBps()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_DEFAULT_FEE_BPS="$(cast call "$DILIGENCE_ADDRESS" 'DEFAULT_FEE_BPS()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_FEE_BPS_FROZEN="$(cast call "$DILIGENCE_ADDRESS" 'feeBpsFrozen()(bool)' --rpc-url "$RPC_URL")"
DILIGENCE_COMPUTE_SETTLEMENT_BPS="$(cast call "$DILIGENCE_ADDRESS" 'COMPUTE_SETTLEMENT_BPS()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
DILIGENCE_COMPUTE_SETTLEMENT_POLICY_ENABLED="$(cast call "$DILIGENCE_ADDRESS" 'computeSettlementPolicyEnabled()(bool)' --rpc-url "$RPC_URL")"

ENCUMBRANCE_OWNER="$(cast call "$ENCUMBRANCE_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_OWNER="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingOwner()(address)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_ACCOUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'accountCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_MAX_ADD="$(cast call "$ENCUMBRANCE_ADDRESS" 'maxAddBalanceWei()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_MAX_SPEND="$(cast call "$ENCUMBRANCE_ADDRESS" 'maxSpendWei()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'approvedComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_COMPOSE_COUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'approvedComposeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'managerRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_MANAGER_COUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'managerCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_RELEASE_COMMITMENT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_RELEASE_MAX_ADD="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseMaxAddBalanceWei()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_RELEASE_MAX_SPEND="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseMaxSpendWei()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_RELEASE_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_RELEASE_COMPOSE_COUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseComposeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_RELEASE_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseManagerRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_RELEASE_MANAGER_COUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'releaseManagerCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_PENDING_ACCOUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingAccountCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_MAX_ADD="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingMaxAddBalanceWei()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_PENDING_MAX_SPEND="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingMaxSpendWei()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_PENDING_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingComposeRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingManagerRoot()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_COMMITMENT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyCommitment()(bytes32)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_PENDING_AT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingReleasePolicyActivatesAt()(uint64)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_PENDING_COMPOSE_COUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingComposeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_PENDING_MANAGER_COUNT="$(cast call "$ENCUMBRANCE_ADDRESS" 'pendingManagerCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_POLICY_FROZEN="$(cast call "$ENCUMBRANCE_ADDRESS" 'releasePolicyFrozen()(bool)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_EMERGENCY_HALTED="$(cast call "$ENCUMBRANCE_ADDRESS" 'emergencyHalted()(bool)' --rpc-url "$RPC_URL")"
ENCUMBRANCE_EXPECTED_EMPTY_COMPOSE_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'computeComposeRoot(bytes32[])(bytes32)' '[]' --rpc-url "$RPC_URL")"
ENCUMBRANCE_EXPECTED_EMPTY_MANAGER_ROOT="$(cast call "$ENCUMBRANCE_ADDRESS" 'computeManagerRoot(address[])(bytes32)' '[]' --rpc-url "$RPC_URL")"

CHALLENGE_OWNER="$(cast call "$CHALLENGE_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
CHALLENGE_PENDING_OWNER="$(cast call "$CHALLENGE_ADDRESS" 'pendingOwner()(address)' --rpc-url "$RPC_URL")"
CHALLENGE_PAUSED="$(cast call "$CHALLENGE_ADDRESS" 'registryPaused()(bool)' --rpc-url "$RPC_URL")"
CHALLENGE_COUNT="$(cast call "$CHALLENGE_ADDRESS" 'challengeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
CHALLENGE_NEXT_ID="$(cast call "$CHALLENGE_ADDRESS" 'nextChallengeId()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
CHALLENGE_MIN_VERSION_REVIEW_DELAY="$(cast call "$CHALLENGE_ADDRESS" 'MIN_VERSION_REVIEW_DELAY()(uint64)' --rpc-url "$RPC_URL" | awk '{print $1}')"

COMPUTE_VAULT_OWNER="$(cast call "$COMPUTE_VAULT_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_DEVELOPER_READ="$(cast call "$COMPUTE_VAULT_ADDRESS" 'developer()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_METERING_VERIFIER_READ="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_METERING_QVL_VERIFIER_READ="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringQvlVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_METERING_POLICY_SET_HASH="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringPolicySetHash()(bytes32)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_VERIFIER="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_QVL_VERIFIER="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringQvlVerifier()(address)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_POLICY_SET_HASH="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringPolicySetHash()(bytes32)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PENDING_METERING_AT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingMeteringBindingActivatesAt()(uint64)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_METERING_BINDING_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'meteringBindingFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_PAUSED="$(cast call "$COMPUTE_VAULT_ADDRESS" 'paused()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_FEE_BPS="$(cast call "$COMPUTE_VAULT_ADDRESS" 'developerFeeBps()(uint16)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_FEE_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'developerFeeFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_ALLOWED_ASSET_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'allowedAssetCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_ACTIVE_RATE_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'activeRatePolicyCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_APPROVED_COMPOSE_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'approvedComposeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_APPROVED_TEE_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'approvedTeeIdentityCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_PENDING_ASSET_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingAssetCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_PENDING_RATE_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingRatePolicyCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_PENDING_COMPOSE_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingComposeCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_PENDING_TEE_COUNT="$(cast call "$COMPUTE_VAULT_ADDRESS" 'pendingTeeIdentityCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
COMPUTE_VAULT_COMPOSE_POLICY_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'composePolicyFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_TEE_ADDITIONS_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'teeIdentityAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_RATE_ADDITIONS_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'ratePolicyAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
COMPUTE_VAULT_ASSET_ADDITIONS_FROZEN="$(cast call "$COMPUTE_VAULT_ADDRESS" 'assetAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"

EMAIL_ORACLE_OWNER="$(cast call "$EMAIL_ORACLE_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_PENDING_OWNER="$(cast call "$EMAIL_ORACLE_ADDRESS" 'pendingOwner()(address)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_PRODUCTION_RELEASE="$(cast call "$EMAIL_ORACLE_ADDRESS" 'productionRelease()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_DELAY="$(cast call "$EMAIL_ORACLE_ADDRESS" 'ORACLE_UPGRADE_DELAY()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EMAIL_ORACLE_ALLOW_ANY="$(cast call "$EMAIL_ORACLE_ADDRESS" 'allowAnyDevice()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_CODE_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'oracleCodeFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_CONSUMERS_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'consumerRegistryFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_MANAGER_ADDITIONS_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'consumerManagerAdditionsFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_KMS_FROZEN="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsBindingFrozen()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_ALLOWED_COMPOSE_COUNT="$(cast call "$EMAIL_ORACLE_ADDRESS" 'allowedOracleComposeHashCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EMAIL_ORACLE_PENDING_COMPOSE_COUNT="$(cast call "$EMAIL_ORACLE_ADDRESS" 'pendingOracleComposeHashCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EMAIL_ORACLE_ALLOWED_DEVICE_COUNT="$(cast call "$EMAIL_ORACLE_ADDRESS" 'allowedDeviceIdCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EMAIL_ORACLE_MANAGER_COUNT="$(cast call "$EMAIL_ORACLE_ADDRESS" 'consumerManagerCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EMAIL_ORACLE_CONSUMER_COMPOSE_COUNT="$(cast call "$EMAIL_ORACLE_ADDRESS" 'totalConsumerComposeHashCount()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
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
EMAIL_ORACLE_KMS_REGISTRATION_BLOCK="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsRegistrationBlock()(uint64)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'kmsRegistrationBlockHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_BOOT_INFO_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'targetBootInfoHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RESTART_PROOF_HASH="$(cast call "$EMAIL_ORACLE_ADDRESS" 'restartKeyDerivationProofHash()(bytes32)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_RELEASE_READY="$(cast call "$EMAIL_ORACLE_ADDRESS" 'releaseConfigurationReady()(bool)' --rpc-url "$RPC_URL")"
EMAIL_ORACLE_ZERO_COMPOSE_ALLOWED="$(cast call "$EMAIL_ORACLE_ADDRESS" 'allowedOracleComposeHashes(bytes32)(bool)' "$ZERO_BYTES32" --rpc-url "$RPC_URL")"
EMAIL_ORACLE_ZERO_DEVICE_ALLOWED="$(cast call "$EMAIL_ORACLE_ADDRESS" 'allowedDeviceIds(bytes32)(bool)' "$ZERO_BYTES32" --rpc-url "$RPC_URL")"

EXECUTION_POLICY_ANCHOR_OWNER="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK="$(jq -er \
  '.executionPolicyAnchor.deploymentBlock | tostring' \
  <<<"$DEPLOYMENT_RECEIPTS")"
EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK_HASH="$(jq -er \
  '.executionPolicyAnchor.deploymentBlockHash | ascii_downcase' \
  <<<"$DEPLOYMENT_RECEIPTS")"
PRIMARY_EXECUTION_POLICY_ANCHOR_BLOCK_JSON="$(cast block \
  "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK" \
  --rpc-url "$RPC_URL" \
  --json)"
SECONDARY_EXECUTION_POLICY_ANCHOR_BLOCK_JSON="$(cast block \
  "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK" \
  --rpc-url "$SECONDARY_RPC_URL" \
  --json)"
if [ "${#PRIMARY_EXECUTION_POLICY_ANCHOR_BLOCK_JSON}" -gt 1048576 ] \
  || [ "${#SECONDARY_EXECUTION_POLICY_ANCHOR_BLOCK_JSON}" -gt 1048576 ]; then
  echo "RPC anchor deployment block evidence exceeds the 1 MiB per-response bound." >&2
  exit 1
fi
PRIMARY_EXECUTION_POLICY_ANCHOR_BLOCK_HASH="$(jq -er \
  '.hash | select(type == "string" and test("^0x[0-9a-fA-F]{64}$")) | ascii_downcase' \
  <<<"$PRIMARY_EXECUTION_POLICY_ANCHOR_BLOCK_JSON")"
SECONDARY_EXECUTION_POLICY_ANCHOR_BLOCK_HASH="$(jq -er \
  '.hash | select(type == "string" and test("^0x[0-9a-fA-F]{64}$")) | ascii_downcase' \
  <<<"$SECONDARY_EXECUTION_POLICY_ANCHOR_BLOCK_JSON")"
if [ "$PRIMARY_EXECUTION_POLICY_ANCHOR_BLOCK_HASH" \
    != "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK_HASH" ] \
  || [ "$SECONDARY_EXECUTION_POLICY_ANCHOR_BLOCK_HASH" \
    != "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK_HASH" ]; then
  echo "Primary receipt and both RPCs do not agree on the ExecutionPolicyAnchor deployment block hash." >&2
  exit 1
fi
EXECUTION_POLICY_ANCHOR_DEPLOYMENT_INTENT_SHA256_BYTES32_PRIMARY="$(cast call \
  "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  'deploymentIntentSha256()(bytes32)' \
  --block "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK" \
  --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_REVIEWER_GENESIS_ACCEPTANCE_SHA256_BYTES32_PRIMARY="$(cast call \
  "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  'reviewerAuthorityGenesisAcceptanceSha256()(bytes32)' \
  --block "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK" \
  --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_DEPLOYMENT_INTENT_SHA256_BYTES32_SECONDARY="$(cast call \
  "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  'deploymentIntentSha256()(bytes32)' \
  --block "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK" \
  --rpc-url "$SECONDARY_RPC_URL")"
EXECUTION_POLICY_ANCHOR_REVIEWER_GENESIS_ACCEPTANCE_SHA256_BYTES32_SECONDARY="$(cast call \
  "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
  'reviewerAuthorityGenesisAcceptanceSha256()(bytes32)' \
  --block "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK" \
  --rpc-url "$SECONDARY_RPC_URL")"
EXECUTION_POLICY_ANCHOR_WRITER="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writer()(address)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_WRITER_RELEASE="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerReleaseCommitment()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_PENDING_WRITER="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriter()(address)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_PENDING_RELEASE="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriterReleaseCommitment()(bytes32)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_PENDING_AT="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'pendingWriterActivatesAt()(uint64)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EXECUTION_POLICY_ANCHOR_ROTATIONS_FROZEN="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'writerRotationsFrozen()(bool)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_PAUSED="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'paused()(bool)' --rpc-url "$RPC_URL")"
EXECUTION_POLICY_ANCHOR_GLOBAL_SEQUENCE="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalSequence()(uint256)' --rpc-url "$RPC_URL" | awk '{print $1}')"
EXECUTION_POLICY_ANCHOR_GLOBAL_HEAD="$(cast call "$EXECUTION_POLICY_ANCHOR_ADDRESS" 'globalHead()(bytes32)' --rpc-url "$RPC_URL")"

assert_address_equal "DiligenceRoom developer" "$DEPLOYMENT_OPERATOR" "$DILIGENCE_DEVELOPER"
if [ "$DILIGENCE_PRODUCTION_RELEASE" != "true" ] || [ "$DILIGENCE_DEAL_COUNT" != "0" ]; then
  echo "DiligenceRoom must be constructor-bound to production mode with zero deployment-window deals." >&2
  exit 1
fi
assert_address_equal "DiligenceRoom initial result verifier" "$(cast address-zero)" "$DILIGENCE_VERIFIER"
assert_address_equal "DiligenceRoom pending result verifier" "$(cast address-zero)" "$DILIGENCE_PENDING_VERIFIER"
if [ "$DILIGENCE_PENDING_VERIFIER_AT" != "0" ] || [ "$DILIGENCE_VERIFIER_FROZEN" != "false" ]; then
  echo "DiligenceRoom result verifier must be unset, have no pending proposal, and remain unfrozen at fresh deployment." >&2
  exit 1
fi
assert_address_equal "DiligenceRoom initial attestation verifier" "$(cast address-zero)" "$DILIGENCE_ATTESTATION_VERIFIER"
if [ "$(printf '%s' "$DILIGENCE_ATTESTATION_POLICY_HASH" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ] \
  || [ "$(normalize_address "$DILIGENCE_PENDING_ATTESTATION_VERIFIER")" != "$(normalize_address "$(cast address-zero)")" ] \
  || [ "$(printf '%s' "$DILIGENCE_PENDING_ATTESTATION_POLICY_HASH" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ] \
  || [ "$DILIGENCE_PENDING_ATTESTATION_AT" != "0" ] \
  || [ "$DILIGENCE_ATTESTATION_BINDING_FROZEN" != "false" ]; then
  echo "DiligenceRoom attestation binding must be unset and unfrozen at fresh deployment." >&2
  exit 1
fi
EXPECTED_EMPTY_EVALUATOR_POLICIES_ABI="0x$(printf '0%.0s' {1..192})"
if [ "$DILIGENCE_EVALUATOR_POLICIES_ABI" != "$EXPECTED_EMPTY_EVALUATOR_POLICIES_ABI" ] \
  || [ "$DILIGENCE_APPROVED_EVALUATOR_POLICY_COUNT" != "0" ] \
  || [ "$DILIGENCE_PENDING_EVALUATOR_POLICY_COUNT" != "0" ] \
  || [ "$(normalize_hex_word "$DILIGENCE_EVALUATOR_POLICY_SET_ROOT")" != "$ZERO_BYTES32" ] \
  || [ "$DILIGENCE_EVALUATOR_POLICY_SET_FROZEN" != "false" ] \
  || [ "$DILIGENCE_REQUIRED_EVALUATOR_POLICY_COUNT" != "3" ]; then
  echo "DiligenceRoom evaluator-policy authority must be the exact empty three-slot set at fresh deployment." >&2
  exit 1
fi
assert_address_equal "TinkerAccountEncumbrance owner" "$DEPLOYMENT_OPERATOR" "$ENCUMBRANCE_OWNER"
assert_address_equal "TinkerAccountEncumbrance pending owner" "$(cast address-zero)" "$ENCUMBRANCE_PENDING_OWNER"
assert_address_equal "ChallengeRegistry owner" "$DEPLOYMENT_OPERATOR" "$CHALLENGE_OWNER"
assert_address_equal "ChallengeRegistry pending owner" "$(cast address-zero)" "$CHALLENGE_PENDING_OWNER"
assert_address_equal "ComputeCreditVault owner" "$DEPLOYMENT_OPERATOR" "$COMPUTE_VAULT_OWNER"
assert_address_equal "ComputeCreditVault developer" "$COMPUTE_VAULT_DEVELOPER" "$COMPUTE_VAULT_DEVELOPER_READ"
assert_address_equal \
  "ComputeCreditVault initial metering verifier" \
  "$(cast address-zero)" \
  "$COMPUTE_VAULT_METERING_VERIFIER_READ"
assert_address_equal \
  "ComputeCreditVault initial metering QVL verifier" \
  "$(cast address-zero)" \
  "$COMPUTE_VAULT_METERING_QVL_VERIFIER_READ"
assert_address_equal "EmailOracleAuth owner" "$DEPLOYMENT_OPERATOR" "$EMAIL_ORACLE_OWNER"
assert_address_equal "EmailOracleAuth pending owner" "$(cast address-zero)" "$EMAIL_ORACLE_PENDING_OWNER"
if [ "$EMAIL_ORACLE_PRODUCTION_RELEASE" != "true" ]; then
  echo "EmailOracleAuth must be constructor-bound to production mode." >&2
  exit 1
fi
assert_address_equal "ExecutionPolicyAnchor owner" "$DEPLOYMENT_OPERATOR" "$EXECUTION_POLICY_ANCHOR_OWNER"
if [ "$(normalize_hex_word "$EXECUTION_POLICY_ANCHOR_DEPLOYMENT_INTENT_SHA256_BYTES32_PRIMARY")" \
    != "$(normalize_hex_word "$DEPLOYMENT_INTENT_SHA256_BYTES32")" ] \
  || [ "$(normalize_hex_word "$EXECUTION_POLICY_ANCHOR_DEPLOYMENT_INTENT_SHA256_BYTES32_SECONDARY")" \
    != "$(normalize_hex_word "$DEPLOYMENT_INTENT_SHA256_BYTES32")" ] \
  || [ "$(normalize_hex_word "$EXECUTION_POLICY_ANCHOR_REVIEWER_GENESIS_ACCEPTANCE_SHA256_BYTES32_PRIMARY")" \
    != "$(normalize_hex_word "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32")" ] \
  || [ "$(normalize_hex_word "$EXECUTION_POLICY_ANCHOR_REVIEWER_GENESIS_ACCEPTANCE_SHA256_BYTES32_SECONDARY")" \
    != "$(normalize_hex_word "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32")" ]; then
  echo "ExecutionPolicyAnchor immutable authority commitments do not match the reviewed intent and signed genesis acceptance on both RPCs." >&2
  exit 1
fi

if [ "$DILIGENCE_COMPOSE_REQUIRED" != "true" ] \
  || [ "$DILIGENCE_IDENTITY_REQUIRED" != "true" ] \
  || [ "$DILIGENCE_APPROVAL_REQUIREMENTS_FROZEN" != "true" ] \
  || [ "$DILIGENCE_APPROVED_COMPOSE_COUNT" != "0" ] \
  || [ "$DILIGENCE_APPROVED_TEE_COUNT" != "0" ] \
  || [ "$DILIGENCE_PENDING_COMPOSE_COUNT" != "0" ] \
  || [ "$DILIGENCE_PENDING_TEE_COUNT" != "0" ] \
  || [ "$DILIGENCE_COMPOSE_ADDITIONS_FROZEN" != "false" ] \
  || [ "$DILIGENCE_TEE_ADDITIONS_FROZEN" != "false" ] \
  || [ "$DILIGENCE_ZERO_COMPOSE_APPROVED" != "false" ] \
  || [ "$(printf '%s' "$DILIGENCE_ZERO_TEE_COMPOSE" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ]; then
  echo "DiligenceRoom approval requirements must be enabled, frozen, and fail-closed pending CVM binding." >&2
  exit 1
fi
if [ "$DILIGENCE_DEFAULT_FEE_BPS" != "100" ] \
  || [ "$DILIGENCE_FEE_BPS" != "$DILIGENCE_DEFAULT_FEE_BPS" ] \
  || [ "$DILIGENCE_FEE_BPS_FROZEN" != "true" ]; then
  echo "DiligenceRoom fee must be permanently frozen at the audited 100 bps default." >&2
  exit 1
fi
if [ "$DILIGENCE_COMPUTE_SETTLEMENT_BPS" != "100" ] \
  || [ "$DILIGENCE_COMPUTE_SETTLEMENT_POLICY_ENABLED" != "true" ]; then
  echo "DiligenceRoom deterministic compute settlement policy must be enabled at 100 bps." >&2
  exit 1
fi
if [ "$(printf '%s' "$ENCUMBRANCE_ACCOUNT" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" | tr '[:upper:]' '[:lower:]')" ]; then
  echo "Tinker account commitment mismatch." >&2
  exit 1
fi
if [ "$ENCUMBRANCE_MAX_ADD" != "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" ] \
  || [ "$ENCUMBRANCE_MAX_SPEND" != "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI" ]; then
  echo "Tinker funding policy mismatch." >&2
  exit 1
fi
if [ "$(normalize_address "$ENCUMBRANCE_COMPOSE_ROOT")" != "$(normalize_address "$ENCUMBRANCE_EXPECTED_EMPTY_COMPOSE_ROOT")" ] \
  || [ "$ENCUMBRANCE_COMPOSE_COUNT" != "0" ] \
  || [ "$(normalize_address "$ENCUMBRANCE_MANAGER_ROOT")" != "$(normalize_address "$ENCUMBRANCE_EXPECTED_EMPTY_MANAGER_ROOT")" ] \
  || [ "$ENCUMBRANCE_MANAGER_COUNT" != "0" ]; then
  echo "Fresh Tinker compose and manager authority sets must both be empty." >&2
  exit 1
fi
if [ "$(normalize_address "$ENCUMBRANCE_RELEASE_COMMITMENT")" != "$ZERO_BYTES32" ] \
  || [ "$ENCUMBRANCE_RELEASE_MAX_ADD" != "0" ] \
  || [ "$ENCUMBRANCE_RELEASE_MAX_SPEND" != "0" ] \
  || [ "$(normalize_address "$ENCUMBRANCE_RELEASE_COMPOSE_ROOT")" != "$ZERO_BYTES32" ] \
  || [ "$ENCUMBRANCE_RELEASE_COMPOSE_COUNT" != "0" ] \
  || [ "$(normalize_address "$ENCUMBRANCE_RELEASE_MANAGER_ROOT")" != "$ZERO_BYTES32" ] \
  || [ "$ENCUMBRANCE_RELEASE_MANAGER_COUNT" != "0" ] \
  || [ "$(normalize_address "$ENCUMBRANCE_PENDING_ACCOUNT")" != "$ZERO_BYTES32" ] \
  || [ "$ENCUMBRANCE_PENDING_MAX_ADD" != "0" ] \
  || [ "$ENCUMBRANCE_PENDING_MAX_SPEND" != "0" ] \
  || [ "$(normalize_address "$ENCUMBRANCE_PENDING_COMPOSE_ROOT")" != "$ZERO_BYTES32" ] \
  || [ "$(normalize_address "$ENCUMBRANCE_PENDING_MANAGER_ROOT")" != "$ZERO_BYTES32" ] \
  || [ "$(normalize_address "$ENCUMBRANCE_PENDING_COMMITMENT")" != "$ZERO_BYTES32" ] \
  || [ "$ENCUMBRANCE_PENDING_AT" != "0" ] \
  || [ "$ENCUMBRANCE_PENDING_COMPOSE_COUNT" != "0" ] \
  || [ "$ENCUMBRANCE_PENDING_MANAGER_COUNT" != "0" ] \
  || [ "$ENCUMBRANCE_POLICY_FROZEN" != "false" ] \
  || [ "$ENCUMBRANCE_EMERGENCY_HALTED" != "true" ]; then
  echo "Fresh Tinker encumbrance must be halted with no active or pending release policy." >&2
  exit 1
fi
if [ "$CHALLENGE_PAUSED" != "false" ] \
  || [ "$CHALLENGE_COUNT" != "0" ] \
  || [ "$CHALLENGE_NEXT_ID" != "1" ] \
  || [ "$CHALLENGE_MIN_VERSION_REVIEW_DELAY" != "172800" ]; then
  echo "ChallengeRegistry did not deploy in its pristine empty state with the audited version-review delay." >&2
  exit 1
fi
if [ "$COMPUTE_VAULT_FEE_BPS" != "$COMPUTE_VAULT_DEVELOPER_FEE_BPS" ] \
  || [ "$COMPUTE_VAULT_FEE_FROZEN" != "true" ]; then
  echo "ComputeCreditVault fee must equal the configured value and be permanently frozen." >&2
  exit 1
fi
if [ "$(printf '%s' "$COMPUTE_VAULT_METERING_POLICY_SET_HASH" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ] \
  || [ "$(normalize_address "$COMPUTE_VAULT_PENDING_METERING_VERIFIER")" != "$(normalize_address "$(cast address-zero)")" ] \
  || [ "$(normalize_address "$COMPUTE_VAULT_PENDING_METERING_QVL_VERIFIER")" != "$(normalize_address "$(cast address-zero)")" ] \
  || [ "$(printf '%s' "$COMPUTE_VAULT_PENDING_METERING_POLICY_SET_HASH" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ] \
  || [ "$COMPUTE_VAULT_PENDING_METERING_AT" != "0" ] \
  || [ "$COMPUTE_VAULT_METERING_BINDING_FROZEN" != "false" ] \
  || [ "$COMPUTE_VAULT_PAUSED" != "true" ] \
  || [ "$COMPUTE_VAULT_ALLOWED_ASSET_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_ACTIVE_RATE_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_APPROVED_COMPOSE_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_APPROVED_TEE_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_PENDING_ASSET_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_PENDING_RATE_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_PENDING_COMPOSE_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_PENDING_TEE_COUNT" != "0" ] \
  || [ "$COMPUTE_VAULT_COMPOSE_POLICY_FROZEN" != "false" ] \
  || [ "$COMPUTE_VAULT_TEE_ADDITIONS_FROZEN" != "false" ] \
  || [ "$COMPUTE_VAULT_RATE_ADDITIONS_FROZEN" != "false" ] \
  || [ "$COMPUTE_VAULT_ASSET_ADDITIONS_FROZEN" != "false" ]; then
  echo "ComputeCreditVault must deploy paused with no metering binding or execution admission." >&2
  exit 1
fi
if [ "$EMAIL_ORACLE_DELAY" != "$EMAIL_ORACLE_UPGRADE_DELAY" ]; then
  echo "EmailOracleAuth upgrade-delay mismatch." >&2
  exit 1
fi
if [ "$EMAIL_ORACLE_ALLOW_ANY" != "false" ] \
  || [ "$EMAIL_ORACLE_CODE_FROZEN" != "false" ] \
  || [ "$EMAIL_ORACLE_CONSUMERS_FROZEN" != "false" ] \
  || [ "$EMAIL_ORACLE_MANAGER_ADDITIONS_FROZEN" != "false" ] \
  || [ "$EMAIL_ORACLE_KMS_FROZEN" != "false" ] \
  || [ "$EMAIL_ORACLE_ALLOWED_COMPOSE_COUNT" != "0" ] \
  || [ "$EMAIL_ORACLE_PENDING_COMPOSE_COUNT" != "0" ] \
  || [ "$EMAIL_ORACLE_ALLOWED_DEVICE_COUNT" != "0" ] \
  || [ "$EMAIL_ORACLE_MANAGER_COUNT" != "0" ] \
  || [ "$EMAIL_ORACLE_CONSUMER_COMPOSE_COUNT" != "0" ] \
  || [ "$EMAIL_ORACLE_RELEASE_READY" != "false" ] \
  || [ "$EMAIL_ORACLE_ZERO_COMPOSE_ALLOWED" != "false" ] \
  || [ "$EMAIL_ORACLE_ZERO_DEVICE_ALLOWED" != "false" ]; then
  echo "EmailOracleAuth did not deploy in its expected mutable, deny-all pre-CVM state." >&2
  exit 1
fi
for zero_email_hash in \
  "$EMAIL_ORACLE_RELEASE_COMPOSE" \
  "$EMAIL_ORACLE_RELEASE_DEVICE" \
  "$EMAIL_ORACLE_RELEASE_CONSUMER_COMPOSE" \
  "$EMAIL_ORACLE_KMS_RUNTIME_HASH" \
  "$EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_HASH" \
  "$EMAIL_ORACLE_KMS_REGISTRATION_TX" \
  "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH" \
  "$EMAIL_ORACLE_BOOT_INFO_HASH" \
  "$EMAIL_ORACLE_RESTART_PROOF_HASH"; do
  if [ "$(normalize_address "$zero_email_hash")" != "$ZERO_BYTES32" ]; then
    echo "Fresh EmailOracleAuth release/KMS commitments must be empty." >&2
    exit 1
  fi
done
for zero_email_address in \
  "$EMAIL_ORACLE_RELEASE_MANAGER" \
  "$EMAIL_ORACLE_RELEASE_APP" \
  "$EMAIL_ORACLE_KMS_CONTRACT" \
  "$EMAIL_ORACLE_KMS_IMPLEMENTATION"; do
  assert_address_equal "Fresh EmailOracleAuth release/KMS address" "$(cast address-zero)" "$zero_email_address"
done
if [ "$EMAIL_ORACLE_KMS_REGISTRATION_BLOCK" != "0" ]; then
  echo "Fresh EmailOracleAuth KMS registration block must be zero." >&2
  exit 1
fi
if [ "$(normalize_address "$EXECUTION_POLICY_ANCHOR_WRITER")" != "$(normalize_address "$(cast address-zero)")" ] \
  || [ "$(normalize_address "$EXECUTION_POLICY_ANCHOR_PENDING_WRITER")" != "$(normalize_address "$(cast address-zero)")" ] \
  || [ "$(printf '%s' "$EXECUTION_POLICY_ANCHOR_WRITER_RELEASE" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ] \
  || [ "$(printf '%s' "$EXECUTION_POLICY_ANCHOR_PENDING_RELEASE" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ] \
  || [ "$EXECUTION_POLICY_ANCHOR_PENDING_AT" != "0" ] \
  || [ "$EXECUTION_POLICY_ANCHOR_ROTATIONS_FROZEN" != "false" ] \
  || [ "$EXECUTION_POLICY_ANCHOR_PAUSED" != "true" ] \
  || [ "$EXECUTION_POLICY_ANCHOR_GLOBAL_SEQUENCE" != "0" ] \
  || [ "$(printf '%s' "$EXECUTION_POLICY_ANCHOR_GLOBAL_HEAD" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ]; then
  echo "ExecutionPolicyAnchor must deploy paused, empty, and without an implicit writer." >&2
  exit 1
fi

echo "DiligenceRoom:             $DILIGENCE_ADDRESS"
echo "TinkerAccountEncumbrance:  $ENCUMBRANCE_ADDRESS"
echo "RoyaltyDistributor:        $ROYALTY_ADDRESS"
echo "ChallengeRegistry:         $CHALLENGE_ADDRESS"
echo "ComputeCreditVault:        $COMPUTE_VAULT_ADDRESS"
echo "EmailOracleAuth:           $EMAIL_ORACLE_ADDRESS"
echo "ExecutionPolicyAnchor:     $EXECUTION_POLICY_ANCHOR_ADDRESS"
echo "Diligence runtime hash:     $DILIGENCE_RUNTIME_CODE_HASH"
echo "Encumbrance runtime hash:   $ENCUMBRANCE_RUNTIME_CODE_HASH"
echo "Royalty runtime hash:       $ROYALTY_RUNTIME_CODE_HASH"
echo "Challenge runtime hash:     $CHALLENGE_RUNTIME_CODE_HASH"
echo "Compute vault runtime hash: $COMPUTE_VAULT_RUNTIME_CODE_HASH"
echo "EmailOracle runtime hash:  $EMAIL_ORACLE_RUNTIME_CODE_HASH"
echo "Policy anchor runtime hash: $EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH"

assert_source_checkout_exact "pre-manifest-commit"
if [ -e "$MANIFEST_PATH" ] || [ -L "$MANIFEST_PATH" ]; then
  echo "Fresh-suite manifest output appeared during deployment; refusing to overwrite it." >&2
  exit 1
fi
mkdir -p "$(dirname "$MANIFEST_PATH")"
if [ -L "$(dirname "$MANIFEST_PATH")" ]; then
  echo "Fresh-suite manifest output directory must not be a symlink." >&2
  exit 1
fi
tmp_manifest="$(mktemp "$(dirname "$MANIFEST_PATH")/.base-sepolia-manifest.tmp.XXXXXX")"
seed_manifest="$(mktemp)"
printf '{}\n' > "$seed_manifest"
manifest_input="$seed_manifest"

DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SOURCE_COMMIT="$RELEASE_SHA"

jq \
  --arg deployedAt "$DEPLOYED_AT" \
  --arg operator "$DEPLOYMENT_OPERATOR" \
  --arg verifier "$DILIGENCE_VERIFIER" \
  --arg sourceCommit "$SOURCE_COMMIT" \
  --arg deploymentIntentSha256 "$DEPLOYMENT_INTENT_SHA256" \
  --arg reviewerAuthorityGenesisAcceptanceSha256 "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256" \
  --arg deploymentReviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --arg deploymentReviewEvidenceSha256 "$DEPLOYMENT_REVIEW_EVIDENCE_SHA256" \
  --argjson deploymentReceipts "$DEPLOYMENT_RECEIPTS" \
  --argjson broadcastTransactions "$BROADCAST_TRANSACTIONS" \
  --arg broadcastTransactionsSha256 "$BROADCAST_TRANSACTIONS_SHA256" \
  --arg diligence "$DILIGENCE_ADDRESS" \
  --arg diligenceTx "$DILIGENCE_TX" \
  --arg diligenceRuntimeCodeHash "$DILIGENCE_RUNTIME_CODE_HASH" \
  --argjson diligenceProductionRelease "$DILIGENCE_PRODUCTION_RELEASE" \
  --arg diligenceDealCount "$DILIGENCE_DEAL_COUNT" \
  --arg diligencePendingVerifier "$DILIGENCE_PENDING_VERIFIER" \
  --arg diligencePendingVerifierAt "$DILIGENCE_PENDING_VERIFIER_AT" \
  --argjson diligenceVerifierFrozen "$DILIGENCE_VERIFIER_FROZEN" \
  --arg diligenceAttestationVerifier "$DILIGENCE_ATTESTATION_VERIFIER" \
  --arg diligenceAttestationPolicyHash "$DILIGENCE_ATTESTATION_POLICY_HASH" \
  --arg diligencePendingAttestationVerifier "$DILIGENCE_PENDING_ATTESTATION_VERIFIER" \
  --arg diligencePendingAttestationPolicyHash "$DILIGENCE_PENDING_ATTESTATION_POLICY_HASH" \
  --arg diligencePendingAttestationAt "$DILIGENCE_PENDING_ATTESTATION_AT" \
  --argjson diligenceAttestationBindingFrozen "$DILIGENCE_ATTESTATION_BINDING_FROZEN" \
  --arg diligenceEvaluatorPoliciesAbi "$DILIGENCE_EVALUATOR_POLICIES_ABI" \
  --arg diligenceApprovedEvaluatorPolicyCount "$DILIGENCE_APPROVED_EVALUATOR_POLICY_COUNT" \
  --arg diligencePendingEvaluatorPolicyCount "$DILIGENCE_PENDING_EVALUATOR_POLICY_COUNT" \
  --arg diligenceEvaluatorPolicySetRoot "$DILIGENCE_EVALUATOR_POLICY_SET_ROOT" \
  --argjson diligenceEvaluatorPolicySetFrozen "$DILIGENCE_EVALUATOR_POLICY_SET_FROZEN" \
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
  --arg executionPolicyAnchorDeploymentIntentSha256Bytes32 "$DEPLOYMENT_INTENT_SHA256_BYTES32" \
  --arg executionPolicyAnchorReviewerGenesisAcceptanceSha256Bytes32 "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32" \
  --arg executionPolicyAnchorAuthorityCommitmentReadProof "$AUTHORITY_COMMITMENT_READ_PROOF" \
  --arg executionPolicyAnchorAuthorityCommitmentReadBlock "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK" \
  --arg executionPolicyAnchorAuthorityCommitmentReadBlockHash "$EXECUTION_POLICY_ANCHOR_AUTHORITY_COMMITMENT_READ_BLOCK_HASH" \
  --arg executionPolicyAnchorOwner "$EXECUTION_POLICY_ANCHOR_OWNER" \
  --arg executionPolicyAnchorWriter "$EXECUTION_POLICY_ANCHOR_WRITER" \
  --arg executionPolicyAnchorWriterRelease "$EXECUTION_POLICY_ANCHOR_WRITER_RELEASE" \
  --arg executionPolicyAnchorPendingWriter "$EXECUTION_POLICY_ANCHOR_PENDING_WRITER" \
  --arg executionPolicyAnchorPendingRelease "$EXECUTION_POLICY_ANCHOR_PENDING_RELEASE" \
  --arg executionPolicyAnchorPendingAt "$EXECUTION_POLICY_ANCHOR_PENDING_AT" \
  --argjson executionPolicyAnchorRotationsFrozen "$EXECUTION_POLICY_ANCHOR_ROTATIONS_FROZEN" \
  --argjson executionPolicyAnchorPaused "$EXECUTION_POLICY_ANCHOR_PAUSED" \
  --arg executionPolicyAnchorGlobalSequence "$EXECUTION_POLICY_ANCHOR_GLOBAL_SEQUENCE" \
  --arg executionPolicyAnchorGlobalHead "$EXECUTION_POLICY_ANCHOR_GLOBAL_HEAD" \
  --argjson verificationRequested "$VERIFY" \
  -f "$MANIFEST_FILTER" \
  "$manifest_input" > "$tmp_manifest"

jq empty "$tmp_manifest"
if ! durably_publish_json "$tmp_manifest" "$MANIFEST_PATH" create 0444; then
  echo "Immutable fresh-suite manifest could not be durably published." >&2
  exit 1
fi
rm -f -- "$tmp_manifest"
tmp_manifest=""
write_broadcast_journal_status \
  "validated_manifest_committed" \
  "Exact 13-transaction validation and fail-closed poststate checks completed; the immutable release-scoped manifest was committed."
BROADCAST_VALIDATED=true

echo
echo "Committed immutable fresh-suite deployment manifest: $MANIFEST_PATH"
echo "No historical deployment ledger or prior Phala evidence was treated as authority input."
echo "Diligence TEE gates are enabled and irreversibly frozen; empty mappings remain fail-closed until verified CVM binding."

if [ "$VERIFY" = "true" ]; then
  echo
  echo "== Submit source verification after ledger recording =="
  DILIGENCE_CONSTRUCTOR_ARGS="$(cast abi-encode 'constructor(bool)' true)"
  ENCUMBRANCE_CONSTRUCTOR_ARGS="$(
    cast abi-encode \
      'constructor(address,bytes32,bytes32,uint256,uint256)' \
      "$DEPLOYMENT_OPERATOR" \
      "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT" \
      "$ZERO_BYTES32" \
      "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI" \
      "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI"
  )"
  CHALLENGE_CONSTRUCTOR_ARGS="$(
    cast abi-encode 'constructor(address)' "$DEPLOYMENT_OPERATOR"
  )"
  COMPUTE_VAULT_CONSTRUCTOR_ARGS="$(
    cast abi-encode \
      'constructor(address,address,uint16)' \
      "$DEPLOYMENT_OPERATOR" \
      "$COMPUTE_VAULT_DEVELOPER" \
      "$COMPUTE_VAULT_DEVELOPER_FEE_BPS"
  )"
  EMAIL_ORACLE_CONSTRUCTOR_ARGS="$(
    cast abi-encode \
      'constructor(address,uint256,bool,bytes32,bytes32,bool)' \
      "$DEPLOYMENT_OPERATOR" \
      "$EMAIL_ORACLE_UPGRADE_DELAY" \
      false \
      "$ZERO_BYTES32" \
      "$ZERO_BYTES32" \
      true
  )"
  EXECUTION_POLICY_ANCHOR_CONSTRUCTOR_ARGS="$(
    cast abi-encode \
      'constructor(address,bytes32,bytes32)' \
      "$DEPLOYMENT_OPERATOR" \
      "$DEPLOYMENT_INTENT_SHA256_BYTES32" \
      "$REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32"
  )"

  forge verify-contract \
    --chain "$CHAIN_ID" \
    --rpc-url "$RPC_URL" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --constructor-args "$DILIGENCE_CONSTRUCTOR_ARGS" \
    "$DILIGENCE_ADDRESS" \
    src/DiligenceRoom.sol:DiligenceRoom

  forge verify-contract \
    --chain "$CHAIN_ID" \
    --rpc-url "$RPC_URL" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --constructor-args "$ENCUMBRANCE_CONSTRUCTOR_ARGS" \
    "$ENCUMBRANCE_ADDRESS" \
    src/TinkerAccountEncumbrance.sol:TinkerAccountEncumbrance

  forge verify-contract \
    --chain "$CHAIN_ID" \
    --rpc-url "$RPC_URL" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    "$ROYALTY_ADDRESS" \
    src/RoyaltyDistributor.sol:RoyaltyDistributor

  forge verify-contract \
    --chain "$CHAIN_ID" \
    --rpc-url "$RPC_URL" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --constructor-args "$CHALLENGE_CONSTRUCTOR_ARGS" \
    "$CHALLENGE_ADDRESS" \
    src/ChallengeRegistry.sol:ChallengeRegistry

  forge verify-contract \
    --chain "$CHAIN_ID" \
    --rpc-url "$RPC_URL" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --constructor-args "$COMPUTE_VAULT_CONSTRUCTOR_ARGS" \
    "$COMPUTE_VAULT_ADDRESS" \
    src/ComputeCreditVault.sol:ComputeCreditVault

  forge verify-contract \
    --chain "$CHAIN_ID" \
    --rpc-url "$RPC_URL" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --constructor-args "$EMAIL_ORACLE_CONSTRUCTOR_ARGS" \
    "$EMAIL_ORACLE_ADDRESS" \
    src/EmailOracleAuth.sol:EmailOracleAuth

  forge verify-contract \
    --chain "$CHAIN_ID" \
    --rpc-url "$RPC_URL" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --constructor-args "$EXECUTION_POLICY_ANCHOR_CONSTRUCTOR_ARGS" \
    "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
    src/ExecutionPolicyAnchor.sol:ExecutionPolicyAnchor

  verification_manifest="$(mktemp "$(dirname "$MANIFEST_PATH")/.base-sepolia-verification.tmp.XXXXXX")"
  manifest_sha256="sha256:$(node -e '
    const fs = require("node:fs");
    const crypto = require("node:crypto");
    process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex"));
  ' "$MANIFEST_PATH")"
  jq -n \
    --arg recordedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg manifestPath "$MANIFEST_PATH" \
    --arg manifestSha256 "$manifest_sha256" \
    --arg releaseSha "$RELEASE_SHA" \
    --arg diligenceRoom "$DILIGENCE_ADDRESS" \
    --arg tinkerAccountEncumbrance "$ENCUMBRANCE_ADDRESS" \
    --arg royaltyDistributor "$ROYALTY_ADDRESS" \
    --arg challengeRegistry "$CHALLENGE_ADDRESS" \
    --arg computeCreditVault "$COMPUTE_VAULT_ADDRESS" \
    --arg emailOracleAuth "$EMAIL_ORACLE_ADDRESS" \
    --arg executionPolicyAnchor "$EXECUTION_POLICY_ANCHOR_ADDRESS" '
      {
        schema: "dnai.basescan-verification-submission-receipt.v1",
        status: "submitted_not_confirmed",
        truthStatus: "submission_commands_succeeded_not_explorer_verification_confirmation",
        recordedAt: $recordedAt,
        releaseSha: $releaseSha,
        immutableDeploymentManifestPath: $manifestPath,
        immutableDeploymentManifestSha256: $manifestSha256,
        contracts: {
          diligenceRoom: $diligenceRoom,
          tinkerAccountEncumbrance: $tinkerAccountEncumbrance,
          royaltyDistributor: $royaltyDistributor,
          challengeRegistry: $challengeRegistry,
          computeCreditVault: $computeCreditVault,
          emailOracleAuth: $emailOracleAuth,
          executionPolicyAnchor: $executionPolicyAnchor
        }
      }
    ' > "$verification_manifest"
  if [ -e "$VERIFICATION_RECEIPT_PATH" ] || [ -L "$VERIFICATION_RECEIPT_PATH" ]; then
    echo "BaseScan submission receipt output appeared during verification; refusing to overwrite it." >&2
    exit 1
  fi
  if ! durably_publish_json "$verification_manifest" "$VERIFICATION_RECEIPT_PATH" create 0444; then
    echo "BaseScan submission receipt could not be durably published." >&2
    exit 1
  fi
  rm -f -- "$verification_manifest"
  verification_manifest=""
  echo "BaseScan verification requests submitted; confirm explorer status before production routing."
fi

trap - EXIT
cleanup
