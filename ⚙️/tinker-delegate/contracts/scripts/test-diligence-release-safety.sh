#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/configure-diligence-release.sh"
MANIFEST_FILTER="$SCRIPT_DIR/update-diligence-release-manifest.jq"
PREFLIGHT_FILTER="$SCRIPT_DIR/preflight-diligence-release-ledger.jq"
ACCEPTANCE_FILTER="$SCRIPT_DIR/verify-diligence-governance-acceptance.jq"
SCRIPT="$SCRIPT_DIR/../script/ConfigureDiligenceRelease.s.sol"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"

bash -n "$HELPER"
bash -n "$POLICY_GUARD"
test -s "$MANIFEST_FILTER"
test -s "$PREFLIGHT_FILTER"
test -s "$ACCEPTANCE_FILTER"

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
  '.assertionCount == 36' \
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
dry_run_line="$(grep -n -m1 '^[[:space:]]*forge script' "$HELPER" | cut -d: -f1)"
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
grep -Fq 'operator_policy_assert_public_env contractEnv DILIGENCE_GOVERNANCE_CONTROLLER' "$HELPER"
grep -Fq "resultVerifier()(address)" "$HELPER"
grep -Fq "computeEvaluatorPolicySetRoot(bytes32[3])(bytes32)" "$HELPER"

dry_exit_line="$(grep -n -m1 '^[[:space:]]*if \[ "\$BROADCAST" != "true" \]; then' "$HELPER" | cut -d: -f1)"
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
  'deploymentIntentSha256' \
  'diligenceRoomDeploymentTx' \
  'operatorTransactions' \
  'operatorTransactionsSha256' \
  'diligenceReleaseHistory' \
  'blockTimestamp' \
  'transactionHash'; do
  if ! grep -Fq "$atomic_boundary" "$HELPER" "$MANIFEST_FILTER"; then
    echo "Diligence atomic release evidence is missing: $atomic_boundary" >&2
    exit 1
  fi
done
grep -Fq 'preflight-diligence-release-ledger.jq' "$HELPER"
prebroadcast_line="$(grep -n '^[[:space:]]*preflight_diligence_release_ledger$' "$HELPER" | tail -1 | cut -d: -f1)"
wallet_unlock_line="$(grep -n -m1 'unlocked_signer="\$(cast wallet address --account dev)"' "$HELPER" | cut -d: -f1)"
broadcast_line="$(grep -n -m1 -- '--broadcast' "$HELPER" | cut -d: -f1)"
if [ -z "$prebroadcast_line" ] || [ -z "$wallet_unlock_line" ] || [ -z "$broadcast_line" ] \
  || [ "$prebroadcast_line" -ge "$wallet_unlock_line" ] \
  || [ "$prebroadcast_line" -ge "$broadcast_line" ]; then
  echo "Diligence ledger lineage must be rechecked under lock before wallet unlock and broadcast." >&2
  exit 1
fi
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
for acceptance_boundary in \
  'Phase 4 never broadcasts' \
  'DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE' \
  'DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH' \
  'DILIGENCE_GOVERNANCE_ACCEPTANCE_RECORD' \
  'contract_event_and_state' \
  'finalized_contract_controller_event_and_state_no_trace_claim' \
  'cast block finalized' \
  'exact append-only phase-3 pending governance evidence' \
  'verify-diligence-governance-acceptance.jq'; do
  if ! grep -Fq "$acceptance_boundary" "$HELPER" "$MANIFEST_FILTER" "$ACCEPTANCE_FILTER"; then
    echo "Diligence controller-receipt ceremony is missing: $acceptance_boundary" >&2
    exit 1
  fi
done
for boundary in \
  'RELEASE_SHA must equal the exact lowercase checked-out commit' \
  'Refusing governance broadcast from a dirty source tree' \
  'RPC chainId $live_chain_id is not Base Sepolia' \
  'runtime code does not match the reviewed release hash' \
  'operator does not own an unencumbered DiligenceRoom'; do
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
  'room.freezeTeeIdentityAdditions()' \
  'room.proposeDeveloper(governanceController)' \
  'room.acceptDeveloper()'; do
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
phase_four_output="$fixture_dir/phase-four.json"
bad_input="$fixture_dir/bad.json"
bad_output="$fixture_dir/bad-output.json"

room_address=0x1111111111111111111111111111111111111111
deployment_operator=0x5555555555555555555555555555555555555555
governance_controller=0x6666666666666666666666666666666666666666
runtime_hash=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=0123456789abcdef0123456789abcdef01234567
review_envelope_hash=sha256:abababababababababababababababababababababababababababababababab
review_envelope_hash_1=sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
review_envelope_hash_2=sha256:a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2
review_envelope_hash_3=sha256:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
review_envelope_hash_4=sha256:a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4
final_authority_hash=sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
deployment_intent_hash=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
room_deployment_tx=0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
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
  --arg deploymentIntent "$deployment_intent_hash" \
  --arg deploymentReview "sha256:$(printf 'e%.0s' {1..64})" \
  --arg operator "$deployment_operator" \
  --arg controller "$governance_controller" \
  --arg deploymentTx "$room_deployment_tx" \
  --arg zeroAddress "$zero_address" \
  '{
    schemaVersion: 2,
    network: {name: "Base Sepolia", chainId: 84532, untouchedNetworkField: true},
    contracts: {
      diligenceRoom: {
        address: $room,
        runtimeCodeHash: $runtime,
        sourceCommit: $source,
        developer: $operator,
        initialDeveloper: $operator,
        releaseGovernanceController: $controller,
        protocolFeeRecipient: $controller,
        pendingDeveloper: $zeroAddress,
        pendingDeveloperActivatesAt: 0,
        developerTransferDelaySeconds: 172800,
        deploymentTx: $deploymentTx,
        feeBps: 100,
        nestedCanary: {preserve: [1, 2, 3]}
      },
      unrelatedContract: {address: "preserve-unrelated-contract", nested: {value: 9}}
    },
    freshDeployment: {contractSuite: {
      sourceCommit: $source,
      deploymentIntentSha256: $deploymentIntent,
      deploymentReviewEnvelopeSha256: $deploymentReview,
      broadcastTransactions: [{
        sequence: 0,
        contractKey: "diligenceRoom",
        contractName: "DiligenceRoom",
        transactionType: "CREATE",
        functionSignature: "constructor(bool,address)",
        transactionHash: $deploymentTx,
        transactionFrom: $operator,
        receiptContractAddress: $room
      }],
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
  local active_developer pending_developer pending_developer_at
  local acceptance_mode acceptance_claim finalized_through_block
  local phase_review_envelope transaction_functions transaction_hash_nibbles
  local operator_transactions operator_transactions_sha256_json

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
      active_developer="$deployment_operator"; pending_developer="$zero_address"
      pending_developer_at=0
      acceptance_mode=not_applicable
      acceptance_claim=operator_forge_broadcast_receipt
      finalized_through_block=0
      phase_review_envelope="$review_envelope_hash_1"
      transaction_functions='["proposeComposeAndEvaluatorPolicySet(bytes32,bytes32[3])","proposeResultVerifier(address)","proposeAttestationBinding(address,bytes32)"]'
      transaction_hash_nibbles='["1","2","a"]'
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
      active_developer="$deployment_operator"; pending_developer="$zero_address"
      pending_developer_at=0
      acceptance_mode=not_applicable
      acceptance_claim=operator_forge_broadcast_receipt
      finalized_through_block=0
      phase_review_envelope="$review_envelope_hash_2"
      transaction_functions='["activateComposeAndEvaluatorPolicySet(bytes32,bytes32[3])","activateResultVerifier()","freezeResultVerifier()","activateAttestationBinding()","freezeAttestationBinding()","proposeTeeIdentity(address,bytes32)"]'
      transaction_hash_nibbles='["3","4","5","6","7","b"]'
      ;;
    3)
      status=deployed_exact_diligence_release_policy_frozen_pending_governance_timelock
      policy_state=fail_closed_exact_policy_pending_governance_acceptance
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
      active_developer="$deployment_operator"; pending_developer="$governance_controller"
      pending_developer_at=1700172803
      acceptance_mode=not_applicable
      acceptance_claim=operator_forge_broadcast_receipt
      finalized_through_block=0
      phase_review_envelope="$review_envelope_hash_3"
      transaction_functions='["activateTeeIdentity(address)","freezeComposeAndEvaluatorPolicySets()","freezeTeeIdentityAdditions()","proposeDeveloper(address)"]'
      transaction_hash_nibbles='["8","9","f","c"]'
      ;;
    4)
      status=deployed_exact_diligence_release_policy_frozen_active
      policy_state=exact_timelocked_diligence_release_policy_frozen_active
      tx=0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
      block=104
      block_timestamp=1700172804
      recorded_at=2026-01-07T00:00:04Z
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
      active_evaluator_root="$evaluator_policy_root"
      pending_evaluator_1_at=0; pending_evaluator_2_at=0; pending_evaluator_3_at=0
      active_developer="$governance_controller"; pending_developer="$zero_address"
      pending_developer_at=0
      acceptance_mode="${acceptance_mode_override:-contract_event_and_state}"
      acceptance_claim="${acceptance_claim_override:-finalized_contract_controller_event_and_state_no_trace_claim}"
      finalized_through_block="${finalized_through_block_override:-105}"
      phase_review_envelope="$review_envelope_hash_4"
      transaction_functions='[]'
      transaction_hash_nibbles='[]'
      ;;
    *) return 2 ;;
  esac

  if [ "$phase" -lt 4 ]; then
    operator_transactions="$(jq -cn \
      --argjson functions "$transaction_functions" \
      --argjson nibbles "$transaction_hash_nibbles" \
      --arg sender "$deployment_operator" \
      --arg target "$room_address" \
      --argjson finalBlock "$block" '
        [range(0; ($functions | length)) as $sequence
          | ($nibbles[$sequence]) as $nibble
          | {
              sequence: $sequence,
              transactionHash: ("0x" + ($nibble * 64)),
              sender: $sender,
              target: $target,
              functionSignature: $functions[$sequence],
              calldataSha256: ("sha256:" + ($nibble * 64)),
              receiptStatus: "success",
              blockNumber: ($finalBlock - (($functions | length) - 1 - $sequence)),
              blockHash: ("0x" + ($nibble * 64))
            }
        ]
      ')"
    operator_transactions_sha256="sha256:$(jq -cS . <<<"$operator_transactions" \
      | shasum -a 256 | awk '{print $1}')"
    operator_transactions_sha256_json="$(jq -cn --arg value "$operator_transactions_sha256" '$value')"
  else
    operator_transactions='[]'
    operator_transactions_sha256_json=null
  fi

  jq \
    --argjson chainId 84532 \
    --arg roomAddress "$room_address" \
    --arg runtimeCodeHash "$runtime_hash" \
    --arg sourceCommit "$source_commit" \
    --arg deploymentIntentSha256Expected "$deployment_intent_hash" \
    --arg reviewEnvelopeSha256 "$phase_review_envelope" \
    --arg finalAuthoritySha256 "$final_authority_hash" \
    --argjson phase "$phase" \
    --arg tx "$tx" \
    --argjson block "$block" \
    --argjson blockTimestamp "$block_timestamp" \
    --arg recordedAt "$recorded_at" \
    --arg status "$status" \
    --arg policyState "$policy_state" \
    --arg governanceAcceptanceEvidenceMode "$acceptance_mode" \
    --arg governanceAcceptanceEvidenceClaim "$acceptance_claim" \
    --argjson finalizedThroughBlock "$finalized_through_block" \
    --argjson operatorTransactions "$operator_transactions" \
    --argjson operatorTransactionsSha256 "$operator_transactions_sha256_json" \
    --arg deploymentOperator "$deployment_operator" \
    --arg governanceController "$governance_controller" \
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
    --arg activeDeveloper "$active_developer" \
    --arg pendingDeveloper "$pending_developer" \
    --argjson pendingDeveloperActivatesAt "$pending_developer_at" \
    --argjson developerTransferDelaySeconds 172800 \
    --argjson composeFrozen "$compose_frozen" \
    --argjson teeFrozen "$tee_frozen" \
    --argjson evaluatorPolicySetFrozen "$evaluator_frozen" \
    -f "$MANIFEST_FILTER" "$input" > "$output"
}

preflight_phase() {
  local input="$1"
  local phase="$2"
  jq \
    --argjson chainId 84532 \
    --argjson phase "$phase" \
    --arg roomAddress "$room_address" \
    --arg runtimeCodeHash "$runtime_hash" \
    --arg sourceCommit "$source_commit" \
    --arg deploymentIntentSha256Expected "$deployment_intent_hash" \
    --arg finalAuthoritySha256 "$final_authority_hash" \
    --arg deploymentOperator "$deployment_operator" \
    --arg governanceController "$governance_controller" \
    -f "$PREFLIGHT_FILTER" "$input"
}

preflight_phase "$fixture_input" 1 >/dev/null
apply_phase "$fixture_input" "$phase_one_output" 1
preflight_phase "$phase_one_output" 2 >/dev/null
apply_phase "$phase_one_output" "$phase_two_output" 2
preflight_phase "$phase_two_output" 3 >/dev/null
apply_phase "$phase_two_output" "$phase_three_output" 3
preflight_phase "$phase_three_output" 4 >/dev/null
apply_phase "$phase_three_output" "$phase_four_output" 4

jq -e -s '
  .[0] as $before
  | .[1] as $after
  | ($before | del(.contracts.diligenceRoom))
      == ($after | del(.contracts.diligenceRoom, .diligenceReleaseHistory))
  and ($before.contracts.diligenceRoom
    | del(.developer, .pendingDeveloper, .pendingDeveloperActivatesAt,
        .developerTransferDelaySeconds)
    | to_entries | all(
    . as $entry | $after.contracts.diligenceRoom[$entry.key] == $entry.value
  ))
' "$fixture_input" "$phase_four_output" >/dev/null

jq -e \
  --arg room "$room_address" \
  --arg runtime "$runtime_hash" \
  --arg source "$source_commit" \
  --arg reviewEnvelope1 "$review_envelope_hash_1" \
  --arg reviewEnvelope2 "$review_envelope_hash_2" \
  --arg reviewEnvelope3 "$review_envelope_hash_3" \
  --arg reviewEnvelope4 "$review_envelope_hash_4" \
  --arg finalAuthority "$final_authority_hash" \
  --arg deploymentIntent "$deployment_intent_hash" \
  --arg roomDeploymentTx "$room_deployment_tx" \
  --arg tee "$tee_identity" \
  --arg compose "$compose_hash" \
  --arg resultVerifier "$result_verifier" \
  --arg evaluatorPolicy1 "$evaluator_policy_1" \
  --arg evaluatorPolicy2 "$evaluator_policy_2" \
  --arg evaluatorPolicy3 "$evaluator_policy_3" \
  --arg evaluatorPolicyRoot "$evaluator_policy_root" \
  --arg governanceController "$governance_controller" \
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
    and .contracts.diligenceRoom.deploymentTx == $roomDeploymentTx
    and .contracts.diligenceRoom.feeBps == 100
    and .contracts.diligenceRoom.nestedCanary == {preserve: [1, 2, 3]}
    and .contracts.diligenceRoom.developer == $governanceController
    and .contracts.diligenceRoom.pendingDeveloper == "0x0000000000000000000000000000000000000000"
    and .contracts.diligenceRoom.pendingDeveloperActivatesAt == 0
    and .contracts.diligenceRoom.developerTransferDelaySeconds == 172800
    and .contracts.diligenceRoom.governanceController == $governanceController
    and .contracts.diligenceRoom.governanceHandoffStatus == "accepted_complete"
    and .contracts.diligenceRoom.governanceAcceptanceEvidenceMode == "contract_event_and_state"
    and .contracts.diligenceRoom.governanceAcceptanceEvidenceClaim
      == "finalized_contract_controller_event_and_state_no_trace_claim"
    and .contracts.diligenceRoom.governanceAcceptanceFinalizedThroughBlock == 105
    and .contracts.diligenceRoom.latestReleasePhase == 4
    and (.contracts.diligenceRoom.latestReleasePhase | type) == "number"
    and .contracts.diligenceRoom.latestReleaseBlock == 104
    and (.contracts.diligenceRoom.latestReleaseBlock | type) == "number"
    and .contracts.diligenceRoom.latestReleaseReviewEnvelopeSha256 == $reviewEnvelope4
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
    and (.diligenceReleaseHistory | length) == 4
    and (.diligenceReleaseHistory | map(.phase)) == [1, 2, 3, 4]
    and (.diligenceReleaseHistory | map(.reviewEnvelopeSha256))
      == [$reviewEnvelope1, $reviewEnvelope2, $reviewEnvelope3, $reviewEnvelope4]
    and (.diligenceReleaseHistory | map(.reviewEnvelopeSha256) | unique | length) == 4
    and (.diligenceReleaseHistory | map(.operatorTransactionCount)) == [3, 6, 4, 0]
    and (.diligenceReleaseHistory | map(.operatorTransactions | length)) == [3, 6, 4, 0]
    and (.diligenceReleaseHistory[0:3] | all(
      (.operatorTransactionsSha256 | test("^sha256:[0-9a-f]{64}$"))
      and ([.operatorTransactions[].sequence]
        == [range(0; (.operatorTransactions | length))])
      and (.operatorTransactions[-1].transactionHash | ascii_downcase)
        == (.transactionHash | ascii_downcase)
      and .operatorTransactions[-1].blockNumber == .blockNumber
    ))
    and .diligenceReleaseHistory[3].operatorTransactions == []
    and .diligenceReleaseHistory[3].operatorTransactionsSha256 == null
    and (.diligenceReleaseHistory | all(
      .chainId == 84532
      and .diligenceRoomAddress == $room
      and .runtimeCodeHash == $runtime
      and .sourceCommit == $source
      and (.reviewEnvelopeSha256 | test("^sha256:[0-9a-f]{64}$"))
      and .finalAuthoritySha256 == $finalAuthority
      and .deploymentIntentSha256 == $deploymentIntent
      and .diligenceRoomDeploymentTx == $roomDeploymentTx
      and .governanceController == $governanceController
      and .resultVerifier == $resultVerifier
      and .evaluatorPolicyCommitments == [$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3]
      and .evaluatorPolicySetRoot == $evaluatorPolicyRoot
      and (.phase | type) == "number"
      and (.blockNumber | type) == "number"
      and (.blockTimestamp | type) == "number"
      and (.recordedAt | type) == "string"
      and (.transactionHash | test("^0x[0-9a-f]{64}$"))
    ))
    and (.diligenceReleaseHistory[0:3] | all(
      .governanceAcceptanceEvidenceMode == "not_applicable"
      and .governanceAcceptanceEvidenceClaim == "operator_forge_broadcast_receipt"
      and .governanceAcceptanceFinalizedThroughBlock == 0
    ))
    and .diligenceReleaseHistory[3].governanceAcceptanceEvidenceMode
      == "contract_event_and_state"
    and .diligenceReleaseHistory[3].governanceAcceptanceEvidenceClaim
      == "finalized_contract_controller_event_and_state_no_trace_claim"
    and .diligenceReleaseHistory[3].governanceAcceptanceFinalizedThroughBlock == 105
  ' "$phase_four_output" >/dev/null

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
  '.contracts.diligenceRoom.initialDeveloper = "0x9999999999999999999999999999999999999999"' \
  '.contracts.diligenceRoom.releaseGovernanceController = "0x9999999999999999999999999999999999999999"' \
  '.contracts.diligenceRoom.protocolFeeRecipient = "0x9999999999999999999999999999999999999999"' \
  '.freshDeployment.contractSuite.sourceCommit = ("9" * 40)' \
  '.freshDeployment.contractSuite.deploymentIntentSha256 = ("sha256:" + ("9" * 64))' \
  '.freshDeployment.contractSuite.broadcastTransactions[0].functionSignature = "constructor(bool)"' \
  '.freshDeployment.contractSuite.broadcastTransactions[0].transactionHash = ("0x" + ("9" * 64))' \
  '.network.chainId = 1' \
  '.diligenceReleaseHistory = {}'; do
  jq "$mutation" "$fixture_input" > "$bad_input"
  assert_filter_rejects "$bad_input" 1
done

# A duplicate phase and a skipped phase must both fail without yielding a
# replacement object. This preserves an exact append-only ceremony sequence.
assert_filter_rejects "$phase_one_output" 1
assert_filter_rejects "$phase_one_output" 3
assert_filter_rejects "$phase_two_output" 4
assert_filter_rejects "$phase_three_output" 3

assert_preflight_rejects() {
  local input="$1"
  local phase="$2"
  if preflight_phase "$input" "$phase" >/dev/null 2>&1; then
    echo "Diligence preflight accepted corrupted lineage or ordered transaction evidence." >&2
    exit 1
  fi
}

# Each phase may carry a fresh, independently validated review envelope, while
# immutable deployment and final-authority lineage and every ordered receipt
# record must remain exact.
for mutation in \
  '.diligenceReleaseHistory[0].reviewEnvelopeSha256 = "sha256:bad"' \
  '.diligenceReleaseHistory[0].deploymentIntentSha256 = ("sha256:" + ("9" * 64))' \
  '.diligenceReleaseHistory[0].diligenceRoomDeploymentTx = ("0x" + ("9" * 64))' \
  '.diligenceReleaseHistory[0].operatorTransactions[0].sender = "0x9999999999999999999999999999999999999999"' \
  '.diligenceReleaseHistory[0].operatorTransactions[0].target = "0x9999999999999999999999999999999999999999"' \
  '.diligenceReleaseHistory[0].operatorTransactions[0].functionSignature = "unreviewed()"' \
  '.diligenceReleaseHistory[0].operatorTransactions |= reverse' \
  '.diligenceReleaseHistory[0].operatorTransactions |= .[0:2]' \
  '.diligenceReleaseHistory[0].operatorTransactionCount = 2'; do
  jq "$mutation" "$phase_one_output" > "$bad_input"
  assert_preflight_rejects "$bad_input" 2
  assert_filter_rejects "$bad_input" 2
done

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

# Phase-4 ledger evidence is mode-specific and finality-bounded.
acceptance_mode_override=unknown
assert_filter_rejects "$phase_three_output" 4
acceptance_mode_override=eoa_direct_call
acceptance_claim_override=finalized_contract_controller_event_and_state_no_trace_claim
assert_filter_rejects "$phase_three_output" 4
acceptance_claim_override=finalized_direct_eoa_call_event_and_state
finalized_through_block_override=103
assert_filter_rejects "$phase_three_output" 4
unset acceptance_mode_override acceptance_claim_override finalized_through_block_override

# The receipt verifier distinguishes a direct EOA call from contract-controller
# event+state evidence. A Safe-style outer call may target the Safe and originate
# from an owner/relayer; without a trace the verifier deliberately claims only
# the exact finalized DiligenceRoom event plus the independently checked state.
acceptance_tx_hash=0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
relayer=0x7777777777777777777777777777777777777777
developer_transferred_topic="$(cast keccak 'DeveloperTransferred(address,address)')"
accept_developer_selector="$(cast sig 'acceptDeveloper()')"
operator_topic="0x000000000000000000000000${deployment_operator#0x}"
controller_topic="0x000000000000000000000000${governance_controller#0x}"
eoa_acceptance="$fixture_dir/eoa-acceptance.json"
contract_acceptance="$fixture_dir/contract-acceptance.json"
acceptance_bad="$fixture_dir/acceptance-bad.json"

jq -n \
  --arg tx "$acceptance_tx_hash" \
  --arg controller "$governance_controller" \
  --arg room "$room_address" \
  --arg selector "$accept_developer_selector" \
  --arg eventTopic "$developer_transferred_topic" \
  --arg operatorTopic "$operator_topic" \
  --arg controllerTopic "$controller_topic" \
  '{
    transaction: {
      hash: $tx,
      from: $controller,
      to: $room,
      input: $selector,
      chainId: "0x14a34",
      blockNumber: "0x68"
    },
    receipt: {
      transactionHash: $tx,
      status: "0x1",
      blockNumber: "0x68",
      logs: [{
        address: $room,
        topics: [$eventTopic, $operatorTopic, $controllerTopic],
        data: "0x"
      }]
    }
  }' > "$eoa_acceptance"

jq \
  --arg relayer "$relayer" \
  --arg controller "$governance_controller" \
  '.transaction.from = $relayer
    | .transaction.to = $controller
    | .transaction.input = "0x12345678"' \
  "$eoa_acceptance" > "$contract_acceptance"

verify_acceptance() {
  local input="$1"
  local mode="$2"
  jq \
    --arg mode "$mode" \
    --arg txHash "$acceptance_tx_hash" \
    --arg room "$room_address" \
    --arg operator "$deployment_operator" \
    --arg controller "$governance_controller" \
    --arg developerTransferredTopic "$developer_transferred_topic" \
    --arg operatorTopic "$operator_topic" \
    --arg controllerTopic "$controller_topic" \
    --arg acceptDeveloperSelector "$accept_developer_selector" \
    -f "$ACCEPTANCE_FILTER" "$input"
}

verify_acceptance "$eoa_acceptance" eoa_direct_call \
  | jq -e '.claim == "finalized_direct_eoa_call_event_and_state"' >/dev/null
verify_acceptance "$contract_acceptance" contract_event_and_state \
  | jq -e '.claim == "finalized_contract_controller_event_and_state_no_trace_claim"' >/dev/null

assert_acceptance_rejects() {
  local input="$1"
  local mode="$2"
  if verify_acceptance "$input" "$mode" >/dev/null 2>&1; then
    echo "Diligence acceptance verifier accepted adversarial receipt evidence." >&2
    exit 1
  fi
}

for mutation in \
  '.transaction.from = "0x8888888888888888888888888888888888888888"' \
  '.transaction.to = "0x8888888888888888888888888888888888888888"' \
  '.transaction.input = "0x12345678"' \
  '.transaction.chainId = "0x1"' \
  '.transaction.blockNumber = "0x69"' \
  '.receipt.transactionHash = ("0x" + ("e" * 64))' \
  '.receipt.status = "0x0"' \
  '.receipt.logs[0].address = "0x8888888888888888888888888888888888888888"' \
  '.receipt.logs[0].topics[0] = ("0x" + ("e" * 64))' \
  '.receipt.logs[0].topics[1] = ("0x" + ("e" * 64))' \
  '.receipt.logs[0].topics[2] = ("0x" + ("e" * 64))' \
  '.receipt.logs[0].data = "0x00"' \
  '.receipt.logs += [.receipt.logs[0]]'; do
  jq "$mutation" "$eoa_acceptance" > "$acceptance_bad"
  assert_acceptance_rejects "$acceptance_bad" eoa_direct_call
done

# Contract mode ignores outer routing by design, but it must reject every event,
# receipt, chain, and block substitution just as strictly as EOA mode.
for mutation in \
  '.transaction.chainId = "0x1"' \
  '.transaction.blockNumber = "0x69"' \
  '.receipt.transactionHash = ("0x" + ("e" * 64))' \
  '.receipt.status = "0x0"' \
  '.receipt.logs[0].address = "0x8888888888888888888888888888888888888888"' \
  '.receipt.logs[0].topics[0] = ("0x" + ("e" * 64))' \
  '.receipt.logs[0].topics[1] = ("0x" + ("e" * 64))' \
  '.receipt.logs[0].topics[2] = ("0x" + ("e" * 64))' \
  '.receipt.logs[0].data = "0x00"' \
  '.receipt.logs += [.receipt.logs[0]]'; do
  jq "$mutation" "$contract_acceptance" > "$acceptance_bad"
  assert_acceptance_rejects "$acceptance_bad" contract_event_and_state
done

echo "diligence release helper safety checks passed"
