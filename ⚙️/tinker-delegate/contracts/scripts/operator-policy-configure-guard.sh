#!/usr/bin/env bash

# Shared fail-closed boundary for production post-deployment configuration.
#
# The retired reviewed packet and its unbound environment projection are never
# accepted here. This guard validates the immutable deployment intent, the
# semantically normalized/domain-separated final authority, and the renewable
# review envelope as three separate artifacts. Its code-owned projector then
# derives the exact 31 public values asserted by the release ceremonies.

OPERATOR_POLICY_CEREMONY_PROJECTION=""
RELEASE_CEREMONY_LOCK_PROTOCOL="dnai.release-ceremony-lock.v1"
RELEASE_CEREMONY_LOCK_OWNER_TOKEN=""
RELEASE_CEREMONY_LOCK_WRITER_ID=""

cleanup_operator_policy_projection() {
  OPERATOR_POLICY_CEREMONY_PROJECTION=""
}

operator_policy_acquire_release_ceremony_lock() {
  local writer_id="$1"
  local result
  require_env RELEASE_CEREMONY_LOCK_ROOT
  if [ -n "$RELEASE_CEREMONY_LOCK_OWNER_TOKEN" ]; then
    echo "Release ceremony lock is already held by this process." >&2
    return 1
  fi
  if ! result="$(node "$ROOT_DIR/scripts/release-ceremony-lock.mjs" acquire \
    --lock-root "$RELEASE_CEREMONY_LOCK_ROOT" \
    --repository-root "$ROOT_DIR" \
    --release-sha "$RELEASE_SHA" \
    --writer-id "$writer_id" \
    --owner-pid "$$")"; then
    echo "The release-wide ceremony lock is held, stale, or invalid; no broadcast was attempted." >&2
    return 1
  fi
  if [ "${#result}" -gt 8192 ] || ! jq -e \
    --arg protocol "$RELEASE_CEREMONY_LOCK_PROTOCOL" '
      keys == ["lock_path", "owner_token", "protocol"]
      and .protocol == $protocol
      and (.lock_path | type == "string" and length > 0)
      and (.owner_token | type == "string" and test("^[0-9a-f]{64}$"))
    ' <<<"$result" >/dev/null; then
    echo "Release ceremony lock acquisition returned malformed ownership evidence; reviewed recovery is required." >&2
    return 1
  fi
  RELEASE_CEREMONY_LOCK_OWNER_TOKEN="$(jq -r '.owner_token' <<<"$result")"
  RELEASE_CEREMONY_LOCK_WRITER_ID="$writer_id"
}

operator_policy_release_release_ceremony_lock() {
  if [ -z "$RELEASE_CEREMONY_LOCK_OWNER_TOKEN" ]; then
    return 0
  fi
  if ! node "$ROOT_DIR/scripts/release-ceremony-lock.mjs" release \
    --lock-root "$RELEASE_CEREMONY_LOCK_ROOT" \
    --repository-root "$ROOT_DIR" \
    --release-sha "$RELEASE_SHA" \
    --writer-id "$RELEASE_CEREMONY_LOCK_WRITER_ID" \
    --owner-token "$RELEASE_CEREMONY_LOCK_OWNER_TOKEN" >/dev/null; then
    echo "Release ceremony lock could not be released; it remains fail-closed pending explicit reviewed recovery." >&2
    return 1
  fi
  RELEASE_CEREMONY_LOCK_OWNER_TOKEN=""
  RELEASE_CEREMONY_LOCK_WRITER_ID=""
}

operator_policy_durably_replace_release_ledger() {
  local source_path="$1"
  local output_path="$2"
  local output_mode
  local -a command
  if [ -z "$RELEASE_CEREMONY_LOCK_OWNER_TOKEN" ]; then
    echo "Refusing release-ledger publication without the held release-wide ceremony lock." >&2
    return 1
  fi
  if output_mode="$(stat -f '%Lp' "$output_path" 2>/dev/null)"; then
    :
  else
    output_mode="$(stat -c '%a' "$output_path")"
  fi
  if [[ ! "$output_mode" =~ ^[0-7]{3,4}$ ]]; then
    echo "Release ledger mode is not canonical octal." >&2
    return 1
  fi
  command=(
    node "$ROOT_DIR/scripts/durable-json-write.mjs"
    --source "$source_path"
    --out "$output_path"
    --publish-mode replace
    --file-mode "$output_mode"
  )
  if [ -n "${RELEASE_CEREMONY_DURABILITY_FAULT_STAGE:-}" ]; then
    command+=(--fault-stage "$RELEASE_CEREMONY_DURABILITY_FAULT_STAGE")
  fi
  "${command[@]}" >/dev/null
}

operator_policy_normalize_public_value() {
  local value="$1"
  case "$value" in
    0x*) printf '%s' "$value" | tr '[:upper:]' '[:lower:]' ;;
    *) printf '%s' "$value" ;;
  esac
}

operator_policy_require_absolute_regular_file() {
  local name="$1"
  local value="${!name:-}"
  require_env "$name"
  if [[ "$value" != /* ]] || [ ! -f "$value" ] || [ -L "$value" ] || [ ! -r "$value" ]; then
    echo "$name must be an absolute, readable, non-symlink regular file." >&2
    exit 1
  fi
}

operator_policy_require_sha256() {
  local name="$1"
  local value="${!name:-}"
  require_env "$name"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [[ "$value" =~ ^sha256:0{64}$ ]]; then
    echo "$name must be a nonzero lowercase sha256:<64-hex> digest." >&2
    exit 1
  fi
}

operator_policy_assert_current_source() {
  local reviewed_head dirty_state
  reviewed_head="$(git -C "$ROOT_DIR" rev-parse HEAD | tr '[:upper:]' '[:lower:]')"
  if [ "$reviewed_head" != "$RELEASE_SHA" ]; then
    echo "RELEASE_SHA from the reviewed authority artifacts does not equal the checked-out Git commit." >&2
    exit 1
  fi
  dirty_state="$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)"
  if [ -n "$dirty_state" ]; then
    echo "Refusing release configuration from source that differs from the reviewed commit." >&2
    exit 1
  fi
}

operator_policy_require_fresh_release_ledger() {
  if [ -z "${MANIFEST_PATH:-}" ] || [[ "$MANIFEST_PATH" != /* ]] \
    || [ ! -f "$MANIFEST_PATH" ] || [ -L "$MANIFEST_PATH" ] || [ ! -r "$MANIFEST_PATH" ]; then
    echo "Release configuration requires an absolute readable non-symlink schemaVersion 2 deployment ledger." >&2
    exit 1
  fi
  if ! jq -e '
    type == "object"
    and .schemaVersion == 2
    and (.notAuthorityForFreshRelease // false) == false
    and (has("supersededBoundary") | not)
    and .status == "fresh_contract_suite_deployed_pending_cvm_binding"
  ' "$MANIFEST_PATH" >/dev/null; then
    echo "Historical schemaVersion 1, superseded, or non-fresh deployment evidence is rejected for release configuration." >&2
    exit 1
  fi
}

operator_policy_validate_authority_artifacts() {
  local intent_receipt review_receipt
  local final_intent_sha final_release_sha

  require_env RELEASE_SHA
  if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || [[ "$RELEASE_SHA" =~ ^0{40}$ ]]; then
    echo "RELEASE_SHA must be the nonzero lowercase 40-hex reviewed Git commit." >&2
    exit 1
  fi
  # Never silently reinterpret the retired packet or accept a JSON projection
  # whose values merely claim to belong to a final-authority digest.
  if [ -n "${OPERATOR_POLICY_PACKET_PATH:-}" ] \
    || [ -n "${OPERATOR_POLICY_PACKET_SHA256:-}" ]; then
    echo "Legacy OPERATOR_POLICY_PACKET_* inputs are retired and rejected." >&2
    exit 1
  fi
  if [ -n "${OPERATOR_POLICY_PROJECTION_PATH:-}" ]; then
    echo "OPERATOR_POLICY_PROJECTION_PATH is rejected; ceremony values are derived by the code-owned cryptographic projector." >&2
    exit 1
  fi

  operator_policy_require_fresh_release_ledger

  operator_policy_require_absolute_regular_file DEPLOYMENT_INTENT_PATH
  operator_policy_require_absolute_regular_file FINAL_RELEASE_AUTHORITY_CORE_PATH
  operator_policy_require_absolute_regular_file OPERATOR_POLICY_REVIEW_ENVELOPE_PATH
  operator_policy_require_sha256 DEPLOYMENT_INTENT_SHA256
  operator_policy_require_sha256 OPERATOR_POLICY_FINAL_AUTHORITY_SHA256
  operator_policy_require_sha256 OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256

  if ! intent_receipt="$(node \
    "$ROOT_DIR/scripts/operator-policy-packet.mjs" \
    check-intent \
    --in "$DEPLOYMENT_INTENT_PATH")"; then
    echo "Deployment-intent validation failed." >&2
    exit 1
  fi
  if [ "${#intent_receipt}" -gt 8192 ] || ! jq -e \
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
    ' <<<"$intent_receipt" >/dev/null; then
    echo "Deployment-intent receipt does not match the reviewed digest, release, or exact schema." >&2
    exit 1
  fi

  # check-review imports the final-authority normalizer and domain-separated
  # digest. It therefore semantically validates FINAL_RELEASE_AUTHORITY_CORE_PATH
  # and binds the exact commitment used by the candidate and anchor.
  if ! review_receipt="$(node \
    "$ROOT_DIR/scripts/operator-policy-packet.mjs" \
    check-review \
    --subject "$FINAL_RELEASE_AUTHORITY_CORE_PATH" \
    --in "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH")"; then
    echo "Final-authority review-envelope validation failed." >&2
    exit 1
  fi
  if [ "${#review_receipt}" -gt 8192 ] || ! jq -e \
    --arg finalSha "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
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
      and .subjectKind == "final_release_authority"
      and .subjectSemanticValidation == "final_release_authority_validated"
      and .subjectSha256 == $finalSha
      and .reviewEnvelopeSha256 == $reviewSha
      and (.reviewEvidenceSha256 | type == "string" and test("^sha256:[0-9a-f]{64}$") and . != "sha256:" + ("0" * 64))
      and .checkpoint == "after_measured_cvms_before_any_release_ceremony_transaction"
      and .actionScopeCount == 8
      and .reviewerDeclarationCount == 2
    ' <<<"$review_receipt" >/dev/null; then
    echo "Authority review receipt does not match the final authority, envelope, or exact schema." >&2
    exit 1
  fi

  # The final core owns the one-way binding to the pre-deployment intent. Read
  # these fields only after check-review has semantically normalized the core.
  if ! final_intent_sha="$(jq -er \
    '.deployment_intent_sha256 | select(type == "string")' \
    "$FINAL_RELEASE_AUTHORITY_CORE_PATH")" \
    || [ "$final_intent_sha" != "$DEPLOYMENT_INTENT_SHA256" ]; then
    echo "Final authority does not bind the exact deployment-intent digest." >&2
    exit 1
  fi
  if ! final_release_sha="$(jq -er \
    '.release_sha | select(type == "string")' \
    "$FINAL_RELEASE_AUTHORITY_CORE_PATH")" \
    || [ "$final_release_sha" != "$RELEASE_SHA" ]; then
    echo "Final authority does not bind RELEASE_SHA." >&2
    exit 1
  fi

  # The anchor helper retains a compatibility path name. It must name the
  # exact already-validated final-authority subject, never a second artifact.
  if [ -n "${EXECUTION_POLICY_RELEASE_CORE_PATH:-}" ]; then
    operator_policy_require_absolute_regular_file EXECUTION_POLICY_RELEASE_CORE_PATH
    if [ "$EXECUTION_POLICY_RELEASE_CORE_PATH" != "$FINAL_RELEASE_AUTHORITY_CORE_PATH" ]; then
      echo "EXECUTION_POLICY_RELEASE_CORE_PATH must equal FINAL_RELEASE_AUTHORITY_CORE_PATH exactly." >&2
      exit 1
    fi
  fi

  operator_policy_assert_current_source
}

operator_policy_project_and_validate() {
  local projection
  operator_policy_validate_authority_artifacts
  if ! projection="$(node \
    "$ROOT_DIR/scripts/ceremony-authority-projector.mjs" \
    --intent "$DEPLOYMENT_INTENT_PATH" \
    --final-authority "$FINAL_RELEASE_AUTHORITY_CORE_PATH" \
    --intent-sha256 "$DEPLOYMENT_INTENT_SHA256" \
    --final-authority-sha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --release-sha "$RELEASE_SHA")"; then
    echo "Cryptographic ceremony environment projection failed." >&2
    exit 1
  fi
  if [ "${#projection}" -gt 32768 ] || ! jq -e \
    --arg intentSha "$DEPLOYMENT_INTENT_SHA256" \
    --arg finalSha "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --arg releaseSha "$RELEASE_SHA" '
      keys == [
        "aliasCount",
        "aliases",
        "assertionCount",
        "assertions",
        "chainId",
        "cvmLaunchIntentSha256",
        "deploymentIntentSha256",
        "finalAuthoritySha256",
        "releaseSha",
        "schema"
      ]
      and .schema == "dnai.ceremony-authority-projection.v1"
      and .releaseSha == $releaseSha
      and .chainId == 84532
      and .deploymentIntentSha256 == $intentSha
      and (.cvmLaunchIntentSha256 | type == "string" and test("^sha256:[0-9a-f]{64}$") and . != "sha256:" + ("0" * 64))
      and .finalAuthoritySha256 == $finalSha
      and .assertionCount == 31
      and .aliasCount == 4
      and (.assertions | type == "object" and length == 31)
      and (.aliases | type == "object" and length == 4)
      and ([.aliases | to_entries[] |
        (.key | type == "string" and test("^[A-Z][A-Z0-9_]{2,95}$"))
        and (.value | type == "string" and test("^[A-Z][A-Z0-9_]{2,95}$"))
      ] | all)
      and ([.assertions[] |
        keys == ["projectionName", "section", "source", "value"]
        and (.section == "contractEnv" or .section == "postDeployEnv")
        and (.projectionName | type == "string" and test("^[A-Z][A-Z0-9_]{2,95}$"))
        and (.source | type == "string" and length > 0 and length <= 256)
        and (.value | type == "string" and length > 0 and length <= 128)
      ] | all)
    ' <<<"$projection" >/dev/null; then
    echo "Cryptographic ceremony projection receipt is malformed or incomplete." >&2
    exit 1
  fi
  OPERATOR_POLICY_CEREMONY_PROJECTION="$projection"
}

operator_policy_assert_public_env() {
  local section="$1"
  local environment_name="$2"
  local projection_name="${3:-$environment_name}"
  local expected_value expected_projection_name
  if [ -z "${!environment_name:-}" ]; then
    echo "$environment_name is required; authority values are never inferred." >&2
    exit 1
  fi
  if [ -z "$OPERATOR_POLICY_CEREMONY_PROJECTION" ]; then
    echo "Cryptographic ceremony projection must be validated before public environment assertions." >&2
    exit 1
  fi
  if ! expected_value="$(jq -er \
    --arg environmentName "$environment_name" \
    --arg section "$section" '
      .assertions[$environmentName]
      | select(.section == $section and .projectionName == $environmentName)
      | .value
      | select(type == "string" and length > 0 and length <= 128)
    ' <<<"$OPERATOR_POLICY_CEREMONY_PROJECTION")"; then
    echo "No exact cryptographic ceremony projection exists for $environment_name in $section." >&2
    exit 1
  fi
  if ! expected_projection_name="$(jq -er \
    --arg environmentName "$environment_name" '
      .aliases[$environmentName] // $environmentName
      | select(type == "string")
    ' <<<"$OPERATOR_POLICY_CEREMONY_PROJECTION")" \
    || [ "$expected_projection_name" != "$projection_name" ]; then
    echo "The projection alias for $environment_name is not the exact reviewed helper mapping." >&2
    exit 1
  fi
  if [ "$(operator_policy_normalize_public_value "${!environment_name}")" \
    != "$(operator_policy_normalize_public_value "$expected_value")" ]; then
    echo "$environment_name does not equal the value derived from the reviewed authority artifacts." >&2
    exit 1
  fi
}
