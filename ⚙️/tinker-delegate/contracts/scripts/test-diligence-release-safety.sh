#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/configure-diligence-release.sh"
MANIFEST_FILTER="$SCRIPT_DIR/update-diligence-release-manifest.jq"
SCRIPT="$SCRIPT_DIR/../script/ConfigureDiligenceRelease.s.sol"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"

bash -n "$HELPER"
bash -n "$POLICY_GUARD"
test -s "$MANIFEST_FILTER"

for policy_boundary in \
  'DEPLOYMENT_INTENT_PATH' \
  'DEPLOYMENT_INTENT_SHA256' \
  'FINAL_RELEASE_AUTHORITY_CORE_PATH' \
  'OPERATOR_POLICY_REVIEW_ENVELOPE_PATH' \
  'OPERATOR_POLICY_FINAL_AUTHORITY_SHA256' \
  'OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256' \
  'operator-policy-packet.mjs' \
  'check-intent' \
  'check-review' \
  'final_release_authority_validated' \
  'ceremony-authority-projector.mjs' \
  'dnai.ceremony-authority-projection.v1' \
  '.assertionCount == 31' \
  'Legacy OPERATOR_POLICY_PACKET_* inputs are retired and rejected' \
  'OPERATOR_POLICY_PROJECTION_PATH is rejected; ceremony values are derived by the code-owned cryptographic projector' \
  'Refusing release configuration from source that differs from the reviewed commit'; do
  if ! grep -Fq "$policy_boundary" "$POLICY_GUARD"; then
    echo "Shared operator-policy guard is missing: $policy_boundary" >&2
    exit 1
  fi
done
for ceremony_digest in \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256; do
  if ! grep -Fq "$ceremony_digest" "$HELPER"; then
    echo "Diligence release is missing exact ceremony digest: $ceremony_digest" >&2
    exit 1
  fi
done
if grep -Eq 'latestReleaseOperatorPolicy|operatorPolicy(Packet|Authority)Sha256' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Diligence release evidence must use finalAuthoritySha256 and reviewEnvelopeSha256 names." >&2
  exit 1
fi
if grep -Eq 'freshDeployment\.contractSuite\.(finalAuthority|reviewEnvelope|operatorPolicy)' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Final authority and ceremony review must never be claimed at fresh contract deployment." >&2
  exit 1
fi
if [ "$(grep -Fc 'operator-policy-packet.mjs' "$POLICY_GUARD")" -ne 2 ] \
  || [ "$(grep -Ec '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER")" -ne 1 ]; then
  echo "Diligence release must validate one intent and one final-authority review envelope." >&2
  exit 1
fi
if grep -Eq 'operator-policy-packet\.mjs.*[[:space:]]project([[:space:]]|$)' "$POLICY_GUARD"; then
  echo "The shared guard must never call the retired packet projection command." >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])eval[[:space:]]|^[[:space:]]*(source|\.)[[:space:]]+.*OPERATOR_POLICY_PROJECTION' "$POLICY_GUARD" "$HELPER"; then
  echo "Operator-policy projection must be read as JSON, never evaluated or sourced." >&2
  exit 1
fi

rejection_log="$(mktemp "${TMPDIR:-/tmp}/dnai-authority-guard-reject.XXXXXX")"
trap 'rm -f -- "$rejection_log"' EXIT
if env RELEASE_SHA="$(printf 'a%.0s' {1..40})" \
  OPERATOR_POLICY_PACKET_PATH=/tmp/retired-packet.json \
  bash -c '
    set -euo pipefail
    ROOT_DIR="$1"
    require_env() { [ -n "${!1:-}" ]; }
    . "$2"
    operator_policy_validate_authority_artifacts
  ' _ "$SCRIPT_DIR/../../../.." "$POLICY_GUARD" >"$rejection_log" 2>&1; then
  echo "The shared guard accepted a retired packet input." >&2
  exit 1
fi
grep -Fq 'Legacy OPERATOR_POLICY_PACKET_* inputs are retired and rejected' "$rejection_log"
if env RELEASE_SHA="$(printf 'b%.0s' {1..40})" \
  OPERATOR_POLICY_PROJECTION_PATH=/tmp/arbitrary-projection.json \
  bash -c '
    set -euo pipefail
    ROOT_DIR="$1"
    require_env() { [ -n "${!1:-}" ]; }
    . "$2"
    operator_policy_validate_authority_artifacts
  ' _ "$SCRIPT_DIR/../../../.." "$POLICY_GUARD" >"$rejection_log" 2>&1; then
  echo "The shared guard accepted an arbitrary environment projection." >&2
  exit 1
fi
grep -Fq 'OPERATOR_POLICY_PROJECTION_PATH is rejected; ceremony values are derived by the code-owned cryptographic projector' "$rejection_log"
rm -f -- "$rejection_log"
trap - EXIT
policy_line="$(grep -n -m1 '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER" | cut -d: -f1)"
wallet_line="$(grep -n -m1 'cast wallet list' "$HELPER" | cut -d: -f1)"
dry_run_line="$(grep -n -m1 '^forge script' "$HELPER" | cut -d: -f1)"
if [ "$policy_line" -ge "$wallet_line" ] || [ "$policy_line" -ge "$dry_run_line" ]; then
  echo "Diligence operator policy must fail closed before wallet access or simulation." >&2
  exit 1
fi
for policy_env in \
  DILIGENCE_TEE_IDENTITY \
  DILIGENCE_COMPOSE_HASH \
  DILIGENCE_ATTESTATION_VERIFIER \
  DILIGENCE_QVL_RELEASE_POLICY_HASH \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1 \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2 \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3 \
  DILIGENCE_EVALUATOR_POLICY_SET_ROOT; do
  grep -Fq "operator_policy_assert_public_env postDeployEnv $policy_env" "$HELPER"
done
grep -Fq 'operator_policy_assert_public_env contractEnv DILIGENCE_RESULT_VERIFIER' "$HELPER"
grep -Fq "resultVerifier()(address)" "$HELPER"
grep -Fq "computeEvaluatorPolicySetRoot(bytes32[3])(bytes32)" "$HELPER"

dry_exit_line="$(grep -n -m1 '^if \[ "\$BROADCAST" != "true" \]; then' "$HELPER" | cut -d: -f1)"
manifest_temp_line="$(grep -n -m1 'DILIGENCE_MANIFEST_TEMP_PATH="\$(mktemp ' "$HELPER" | cut -d: -f1)"
manifest_replace_line="$(grep -n -m1 '^operator_policy_durably_replace_release_ledger "\$DILIGENCE_MANIFEST_TEMP_PATH" "\$MANIFEST_PATH"' "$HELPER" | cut -d: -f1)"
if [ -z "$dry_exit_line" ] || [ -z "$manifest_temp_line" ] || [ -z "$manifest_replace_line" ] \
  || [ "$manifest_temp_line" -le "$dry_exit_line" ] \
  || [ "$manifest_replace_line" -le "$manifest_temp_line" ]; then
  echo "Dry runs must exit before any Diligence deployment-ledger temporary file or replacement." >&2
  exit 1
fi
for atomic_boundary in \
  'Deployment ledger must be an existing non-symlink regular file' \
  'Deployment ledger changed concurrently' \
  'git hash-object --no-filters' \
  'mktemp "$manifest_dir/.${manifest_base}.diligence-release.XXXXXX"' \
  'trap cleanup_diligence_release EXIT' \
  'finalAuthoritySha256' \
  'reviewEnvelopeSha256' \
  'diligenceReleaseHistory' \
  'blockTimestamp' \
  'transactionHash'; do
  if ! grep -Fq "$atomic_boundary" "$HELPER" "$MANIFEST_FILTER"; then
    echo "Diligence atomic release evidence is missing: $atomic_boundary" >&2
    exit 1
  fi
done
if grep -Eq '(^|[[:space:]])(cp|cat)[[:space:]].*MANIFEST_PATH|>[[:space:]]*"?\$MANIFEST_PATH' "$HELPER"; then
  echo "Diligence deployment ledger must only be replaced from a validated same-directory temporary file." >&2
  exit 1
fi

if grep -q -- '--private-key' "$HELPER"; then
  echo "Diligence release helper must never accept raw private keys." >&2
  exit 1
fi
if ! grep -q -- '--account dev' "$HELPER"; then
  echo "Diligence release broadcasts must use the literal dev keystore account." >&2
  exit 1
fi
for boundary in \
  'RELEASE_SHA must equal the exact lowercase checked-out commit' \
  'Refusing governance broadcast from a dirty source tree' \
  'RPC chainId $live_chain_id is not Base Sepolia' \
  'runtime code does not match the reviewed release hash' \
  'operator does not own DiligenceRoom'; do
  if ! grep -Fq "$boundary" "$HELPER" "$SCRIPT"; then
    echo "Diligence release boundary is missing: $boundary" >&2
    exit 1
  fi
done
for phase_call in \
  'room.proposeComposeAndEvaluatorPolicySet(composeHash, evaluatorPolicies)' \
  'room.proposeResultVerifier(resultVerifier)' \
  'room.proposeAttestationBinding(attestationVerifier, qvlReleasePolicyHash)' \
  'room.activateComposeAndEvaluatorPolicySet(composeHash, evaluatorPolicies)' \
  'room.activateResultVerifier()' \
  'room.freezeResultVerifier()' \
  'room.activateAttestationBinding()' \
  'room.freezeAttestationBinding()' \
  'room.proposeTeeIdentity(teeIdentity, composeHash)' \
  'room.activateTeeIdentity(teeIdentity)' \
  'room.freezeComposeAndEvaluatorPolicySets()' \
  'room.freezeTeeIdentityAdditions()'; do
  if ! grep -Fq "$phase_call" "$SCRIPT"; then
    echo "Diligence release phase call is missing: $phase_call" >&2
    exit 1
  fi
done

fixture_dir="$(mktemp -d)"
trap 'rm -rf -- "$fixture_dir"' EXIT
fixture_input="$fixture_dir/input.json"
phase_one_output="$fixture_dir/phase-one.json"
phase_two_output="$fixture_dir/phase-two.json"
phase_three_output="$fixture_dir/phase-three.json"
bad_input="$fixture_dir/bad.json"
bad_output="$fixture_dir/bad-output.json"

room_address=0x1111111111111111111111111111111111111111
runtime_hash=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=0123456789abcdef0123456789abcdef01234567
review_envelope_hash=sha256:abababababababababababababababababababababababababababababababab
final_authority_hash=sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
tee_identity=0x2222222222222222222222222222222222222222
compose_hash=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
attestation_verifier=0x3333333333333333333333333333333333333333
attestation_policy=0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
result_verifier=0x4444444444444444444444444444444444444444
evaluator_policy_1=0x1111111111111111111111111111111111111111111111111111111111111111
evaluator_policy_2=0x2222222222222222222222222222222222222222222222222222222222222222
evaluator_policy_3=0x3333333333333333333333333333333333333333333333333333333333333333
evaluator_policy_root=0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
zero_address=0x0000000000000000000000000000000000000000
zero_bytes32=0x0000000000000000000000000000000000000000000000000000000000000000

jq -n \
  --arg room "$room_address" \
  --arg runtime "$runtime_hash" \
  --arg source "$source_commit" \
  --arg deploymentIntent "sha256:$(printf 'd%.0s' {1..64})" \
  --arg deploymentReview "sha256:$(printf 'e%.0s' {1..64})" \
  '{
    schemaVersion: 2,
    network: {name: "Base Sepolia", chainId: 84532, untouchedNetworkField: true},
    contracts: {
      diligenceRoom: {
        address: $room,
        runtimeCodeHash: $runtime,
        sourceCommit: $source,
        deploymentTx: "preserve-deployment-tx",
        feeBps: 100,
        nestedCanary: {preserve: [1, 2, 3]}
      },
      unrelatedContract: {address: "preserve-unrelated-contract", nested: {value: 9}}
    },
    freshDeployment: {contractSuite: {
      sourceCommit: $source,
      deploymentIntentSha256: $deploymentIntent,
      deploymentReviewEnvelopeSha256: $deploymentReview,
      preserveSuiteField: "untouched"
    }},
    phala: {preserve: {deep: ["all", "evidence"]}},
    unrelatedTopLevel: {preserve: true}
  }' > "$fixture_input"

apply_phase() {
  local input="$1"
  local output="$2"
  local phase="$3"
  local status policy_state tx block block_timestamp recorded_at
  local approved_compose approved_tee pending_compose pending_tee
  local pending_compose_at pending_tee_at
  local active_result_verifier pending_result_verifier pending_result_at result_verifier_frozen
  local approved_evaluator pending_evaluator evaluator_frozen active_evaluator_root
  local pending_evaluator_1_at pending_evaluator_2_at pending_evaluator_3_at
  local active_attestation_verifier active_attestation_policy
  local pending_attestation_verifier pending_attestation_policy pending_attestation_at
  local active_tee_compose pending_tee_compose compose_frozen tee_frozen attestation_frozen

  case "$phase" in
    1)
      status=deployed_diligence_compose_and_qvl_pending_timelock
      policy_state=fail_closed_pending_compose_and_attestation_timelocks
      tx=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      block=101
      block_timestamp=1700000001
      recorded_at=2026-01-01T00:00:01Z
      approved_compose=0; approved_tee=0; pending_compose=1; pending_tee=0
      pending_compose_at=1700000100; pending_tee_at=0
      active_attestation_verifier="$zero_address"; active_attestation_policy="$zero_bytes32"
      pending_attestation_verifier="$attestation_verifier"; pending_attestation_policy="$attestation_policy"
      pending_attestation_at=1700000100
      active_tee_compose="$zero_bytes32"; pending_tee_compose="$zero_bytes32"
      compose_frozen=false; tee_frozen=false; attestation_frozen=false
      active_result_verifier="$zero_address"; pending_result_verifier="$result_verifier"
      pending_result_at=1700000101; result_verifier_frozen=false
      approved_evaluator=0; pending_evaluator=3; evaluator_frozen=false
      active_evaluator_root="$zero_bytes32"
      pending_evaluator_1_at=1700000100; pending_evaluator_2_at=1700000100
      pending_evaluator_3_at=1700000100
      ;;
    2)
      status=deployed_diligence_tee_identity_pending_timelock
      policy_state=fail_closed_pending_tee_identity_timelock
      tx=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      block=102
      block_timestamp=1700000002
      recorded_at=2026-01-03T00:00:02Z
      approved_compose=1; approved_tee=0; pending_compose=0; pending_tee=1
      pending_compose_at=0; pending_tee_at=1700000200
      active_attestation_verifier="$attestation_verifier"; active_attestation_policy="$attestation_policy"
      pending_attestation_verifier="$zero_address"; pending_attestation_policy="$zero_bytes32"
      pending_attestation_at=0
      active_tee_compose="$zero_bytes32"; pending_tee_compose="$compose_hash"
      compose_frozen=false; tee_frozen=false; attestation_frozen=true
      active_result_verifier="$result_verifier"; pending_result_verifier="$zero_address"
      pending_result_at=0; result_verifier_frozen=true
      approved_evaluator=3; pending_evaluator=0; evaluator_frozen=false
      active_evaluator_root="$zero_bytes32"
      pending_evaluator_1_at=0; pending_evaluator_2_at=0; pending_evaluator_3_at=0
      ;;
    3)
      status=deployed_exact_diligence_release_policy_frozen_active
      policy_state=exact_timelocked_diligence_release_policy_frozen_active
      tx=0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      block=103
      block_timestamp=1700000003
      recorded_at=2026-01-05T00:00:03Z
      approved_compose=1; approved_tee=1; pending_compose=0; pending_tee=0
      pending_compose_at=0; pending_tee_at=0
      active_attestation_verifier="$attestation_verifier"; active_attestation_policy="$attestation_policy"
      pending_attestation_verifier="$zero_address"; pending_attestation_policy="$zero_bytes32"
      pending_attestation_at=0
      active_tee_compose="$compose_hash"; pending_tee_compose="$zero_bytes32"
      compose_frozen=true; tee_frozen=true; attestation_frozen=true
      active_result_verifier="$result_verifier"; pending_result_verifier="$zero_address"
      pending_result_at=0; result_verifier_frozen=true
      approved_evaluator=3; pending_evaluator=0; evaluator_frozen=true
      active_evaluator_root="${active_evaluator_root_override:-$evaluator_policy_root}"
      pending_evaluator_1_at=0; pending_evaluator_2_at=0; pending_evaluator_3_at=0
      ;;
    *) return 2 ;;
  esac

  jq \
    --argjson chainId 84532 \
    --arg roomAddress "$room_address" \
    --arg runtimeCodeHash "$runtime_hash" \
    --arg sourceCommit "$source_commit" \
    --arg reviewEnvelopeSha256 "$review_envelope_hash" \
    --arg finalAuthoritySha256 "$final_authority_hash" \
    --argjson phase "$phase" \
    --arg tx "$tx" \
    --argjson block "$block" \
    --argjson blockTimestamp "$block_timestamp" \
    --arg recordedAt "$recorded_at" \
    --arg status "$status" \
    --arg policyState "$policy_state" \
    --arg teeIdentity "$tee_identity" \
    --arg composeHash "$compose_hash" \
    --arg resultVerifier "$result_verifier" \
    --arg evaluatorPolicy1 "$evaluator_policy_1" \
    --arg evaluatorPolicy2 "$evaluator_policy_2" \
    --arg evaluatorPolicy3 "$evaluator_policy_3" \
    --arg evaluatorPolicySetRoot "$evaluator_policy_root" \
    --arg attestationVerifier "$attestation_verifier" \
    --arg attestationPolicyHash "$attestation_policy" \
    --arg activeResultVerifier "$active_result_verifier" \
    --arg pendingResultVerifier "$pending_result_verifier" \
    --argjson pendingResultVerifierActivatesAt "$pending_result_at" \
    --argjson resultVerifierFrozen "$result_verifier_frozen" \
    --arg activeAttestationVerifier "$active_attestation_verifier" \
    --arg activeAttestationPolicyHash "$active_attestation_policy" \
    --arg pendingAttestationVerifier "$pending_attestation_verifier" \
    --arg pendingAttestationPolicyHash "$pending_attestation_policy" \
    --argjson pendingAttestationActivatesAt "$pending_attestation_at" \
    --argjson attestationFrozen "$attestation_frozen" \
    --argjson approvedComposeCount "$approved_compose" \
    --argjson approvedTeeCount "$approved_tee" \
    --argjson pendingComposeCount "$pending_compose" \
    --argjson pendingTeeCount "$pending_tee" \
    --argjson approvedEvaluatorPolicyCount "$approved_evaluator" \
    --argjson pendingEvaluatorPolicyCount "$pending_evaluator" \
    --argjson pendingComposeActivatesAt "$pending_compose_at" \
    --argjson pendingTeeActivatesAt "$pending_tee_at" \
    --argjson pendingEvaluatorPolicy1ActivatesAt "$pending_evaluator_1_at" \
    --argjson pendingEvaluatorPolicy2ActivatesAt "$pending_evaluator_2_at" \
    --argjson pendingEvaluatorPolicy3ActivatesAt "$pending_evaluator_3_at" \
    --arg activeTeeComposeHash "$active_tee_compose" \
    --arg pendingTeeComposeHash "$pending_tee_compose" \
    --arg activeEvaluatorPolicySetRoot "$active_evaluator_root" \
    --argjson composeFrozen "$compose_frozen" \
    --argjson teeFrozen "$tee_frozen" \
    --argjson evaluatorPolicySetFrozen "$evaluator_frozen" \
    -f "$MANIFEST_FILTER" "$input" > "$output"
}

apply_phase "$fixture_input" "$phase_one_output" 1
apply_phase "$phase_one_output" "$phase_two_output" 2
apply_phase "$phase_two_output" "$phase_three_output" 3

jq -e -s '
  .[0] as $before
  | .[1] as $after
  | ($before | del(.contracts.diligenceRoom))
      == ($after | del(.contracts.diligenceRoom, .diligenceReleaseHistory))
  and ($before.contracts.diligenceRoom | to_entries | all(
    . as $entry | $after.contracts.diligenceRoom[$entry.key] == $entry.value
  ))
' "$fixture_input" "$phase_three_output" >/dev/null

jq -e \
  --arg room "$room_address" \
  --arg runtime "$runtime_hash" \
  --arg source "$source_commit" \
  --arg reviewEnvelope "$review_envelope_hash" \
  --arg finalAuthority "$final_authority_hash" \
  --arg tee "$tee_identity" \
  --arg compose "$compose_hash" \
  --arg resultVerifier "$result_verifier" \
  --arg evaluatorPolicy1 "$evaluator_policy_1" \
  --arg evaluatorPolicy2 "$evaluator_policy_2" \
  --arg evaluatorPolicy3 "$evaluator_policy_3" \
  --arg evaluatorPolicyRoot "$evaluator_policy_root" \
  '
    .schemaVersion == 2
    and .network.untouchedNetworkField == true
    and .contracts.unrelatedContract == {address: "preserve-unrelated-contract", nested: {value: 9}}
    and .phala == {preserve: {deep: ["all", "evidence"]}}
    and .unrelatedTopLevel == {preserve: true}
    and .freshDeployment.contractSuite.preserveSuiteField == "untouched"
    and .contracts.diligenceRoom.address == $room
    and .contracts.diligenceRoom.runtimeCodeHash == $runtime
    and .contracts.diligenceRoom.sourceCommit == $source
    and .contracts.diligenceRoom.deploymentTx == "preserve-deployment-tx"
    and .contracts.diligenceRoom.feeBps == 100
    and .contracts.diligenceRoom.nestedCanary == {preserve: [1, 2, 3]}
    and .contracts.diligenceRoom.latestReleasePhase == 3
    and (.contracts.diligenceRoom.latestReleasePhase | type) == "number"
    and .contracts.diligenceRoom.latestReleaseBlock == 103
    and (.contracts.diligenceRoom.latestReleaseBlock | type) == "number"
    and .contracts.diligenceRoom.latestReleaseReviewEnvelopeSha256 == $reviewEnvelope
    and .contracts.diligenceRoom.latestReleaseFinalAuthoritySha256 == $finalAuthority
    and .contracts.diligenceRoom.approvedComposeHashes == [$compose]
    and .contracts.diligenceRoom.approvedTeeIdentities == [$tee]
    and .contracts.diligenceRoom.pendingComposeProposals == []
    and .contracts.diligenceRoom.pendingTeeIdentityProposals == []
    and .contracts.diligenceRoom.resultVerifier == $resultVerifier
    and .contracts.diligenceRoom.pendingResultVerifier == "0x0000000000000000000000000000000000000000"
    and .contracts.diligenceRoom.pendingResultVerifierActivatesAt == 0
    and .contracts.diligenceRoom.resultVerifierFrozen == true
    and .contracts.diligenceRoom.evaluatorPolicyCommitments == [$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3]
    and .contracts.diligenceRoom.evaluatorPolicySetRoot == $evaluatorPolicyRoot
    and .contracts.diligenceRoom.approvedEvaluatorPolicyCount == 3
    and .contracts.diligenceRoom.pendingEvaluatorPolicyCount == 0
    and .contracts.diligenceRoom.evaluatorPolicySetFrozen == true
    and .contracts.diligenceRoom.pendingEvaluatorPolicyProposals == []
    and .contracts.diligenceRoom.composeAdditionsFrozen == true
    and .contracts.diligenceRoom.teeIdentityAdditionsFrozen == true
    and (.diligenceReleaseHistory | length) == 3
    and (.diligenceReleaseHistory | map(.phase)) == [1, 2, 3]
    and (.diligenceReleaseHistory | all(
      .chainId == 84532
      and .diligenceRoomAddress == $room
      and .runtimeCodeHash == $runtime
      and .sourceCommit == $source
      and .reviewEnvelopeSha256 == $reviewEnvelope
      and .finalAuthoritySha256 == $finalAuthority
      and .resultVerifier == $resultVerifier
      and .evaluatorPolicyCommitments == [$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3]
      and .evaluatorPolicySetRoot == $evaluatorPolicyRoot
      and (.phase | type) == "number"
      and (.blockNumber | type) == "number"
      and (.blockTimestamp | type) == "number"
      and (.recordedAt | type) == "string"
      and (.transactionHash | test("^0x[0-9a-f]{64}$"))
    ))
  ' "$phase_three_output" >/dev/null

assert_filter_rejects() {
  local input="$1"
  local phase="$2"
  if apply_phase "$input" "$bad_output" "$phase" >/dev/null 2>&1; then
    echo "Diligence manifest filter accepted adversarial or out-of-order evidence." >&2
    exit 1
  fi
}

for mutation in \
  '.contracts.diligenceRoom.address = "0x9999999999999999999999999999999999999999"' \
  '.contracts.diligenceRoom.runtimeCodeHash = ("0x" + ("9" * 64))' \
  '.contracts.diligenceRoom.sourceCommit = ("9" * 40)' \
  '.freshDeployment.contractSuite.sourceCommit = ("9" * 40)' \
  '.network.chainId = 1' \
  '.diligenceReleaseHistory = {}'; do
  jq "$mutation" "$fixture_input" > "$bad_input"
  assert_filter_rejects "$bad_input" 1
done

# A duplicate phase and a skipped phase must both fail without yielding a
# replacement object. This preserves an exact append-only ceremony sequence.
assert_filter_rejects "$phase_one_output" 1
assert_filter_rejects "$phase_one_output" 3

# The manifest boundary independently rejects malformed policy sets and a
# phase-3 root that does not equal the reviewed exact-set root.
original_policy_1="$evaluator_policy_1"
original_policy_2="$evaluator_policy_2"
original_policy_3="$evaluator_policy_3"
evaluator_policy_2="$evaluator_policy_1"
assert_filter_rejects "$fixture_input" 1
evaluator_policy_1="$original_policy_2"
evaluator_policy_2="$original_policy_1"
assert_filter_rejects "$fixture_input" 1
evaluator_policy_1="$zero_bytes32"
evaluator_policy_2="$original_policy_2"
assert_filter_rejects "$fixture_input" 1
evaluator_policy_1="$original_policy_1"
evaluator_policy_2="$original_policy_2"
evaluator_policy_3="$original_policy_3"
active_evaluator_root_override=0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
assert_filter_rejects "$phase_two_output" 3
unset active_evaluator_root_override

echo "diligence release helper safety checks passed"
