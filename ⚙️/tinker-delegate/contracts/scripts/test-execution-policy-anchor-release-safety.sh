#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/configure-execution-policy-anchor.sh"
SCRIPT="$SCRIPT_DIR/../script/ConfigureExecutionPolicyAnchor.s.sol"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"
MANIFEST_FILTER="$SCRIPT_DIR/update-execution-policy-anchor-release-manifest.jq"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
RELEASE_CORE_CLI="$ROOT_DIR/scripts/execution-policy-release-core-cli.mjs"

TEST_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/execution-policy-anchor-ledger-test.XXXXXX")"
cleanup() {
  rm -rf -- "$TEST_TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

bash -n "$HELPER"
bash -n "$POLICY_GUARD"
jq empty <(jq -n '{}')
test -f "$MANIFEST_FILTER"
test -f "$RELEASE_CORE_CLI"
grep -Fq '. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"' "$HELPER"
test "$(grep -Ec '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER")" -eq 1
policy_line="$(grep -n -m1 '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER" | cut -d: -f1)"
wallet_line="$(grep -n -m1 'cast wallet list' "$HELPER" | cut -d: -f1)"
dry_run_line="$(grep -n -m1 '^forge script' "$HELPER" | cut -d: -f1)"
if [ "$policy_line" -ge "$wallet_line" ] || [ "$policy_line" -ge "$dry_run_line" ]; then
  echo "Execution-policy operator packet must fail closed before wallet access or simulation." >&2
  exit 1
fi
grep -Fq 'operator_policy_assert_public_env postDeployEnv EXECUTION_POLICY_ANCHOR_WRITER' "$HELPER"
grep -Fq 'EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT \' "$HELPER"
grep -Fq 'TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT' "$HELPER"
if grep -Eq '(^|[[:space:]])eval[[:space:]]|^[[:space:]]*(source|\.)[[:space:]]+.*OPERATOR_POLICY_PROJECTION' "$POLICY_GUARD" "$HELPER"; then
  echo "Execution-policy release must never evaluate or source operator-policy projection JSON." >&2
  exit 1
fi

if grep -q -- '--private-key' "$HELPER"; then
  echo "Execution-policy anchor helper must never accept raw private keys." >&2
  exit 1
fi
if ! grep -q -- '--account dev' "$HELPER"; then
  echo "Execution-policy anchor broadcasts must use the literal dev keystore account." >&2
  exit 1
fi
if ! grep -Fq 'execution-policy-release-core-cli.mjs' "$HELPER" \
  || ! grep -Fq 'EXECUTION_POLICY_RELEASE_CORE_PATH' "$HELPER"; then
  echo "Execution-policy anchor helper must derive the writer commitment from the canonical release core." >&2
  exit 1
fi
if ! grep -Fq 'executionPolicyWriterReleaseCommitment' "$RELEASE_CORE_CLI" \
  || ! grep -Fq 'writer_release_commitment' "$RELEASE_CORE_CLI" \
  || grep -Fq 'console.log(`0x${artifact.digest}`)' "$RELEASE_CORE_CLI"; then
  echo "The anchor CLI must emit the launch-intent-bound writer release, never the downstream final-authority digest." >&2
  exit 1
fi
if grep -Fq 'require_env EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT' "$HELPER"; then
  echo "Execution-policy anchor helper must not accept a naked operator-supplied release commitment." >&2
  exit 1
fi
for ledger_boundary in \
  'DEPLOYMENT_MANIFEST_PATH' \
  'update-execution-policy-anchor-release-manifest.jq' \
  'Deployment ledger address, runtime, or source does not match this execution-policy release' \
  'executionPolicyAnchorReleaseHistory' \
  'OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256' \
  'OPERATOR_POLICY_FINAL_AUTHORITY_SHA256' \
  'reviewEnvelopeSha256' \
  'finalAuthoritySha256' \
  'cast receipt "$release_tx" status --confirmations 1' \
  'cast block "$release_block" timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL"' \
  'Deployment ledger changed while the execution-policy release was broadcasting' \
  'Deployment ledger changed during evidence rendering' \
  'mktemp "$(dirname "$MANIFEST_PATH")/.execution-policy-anchor-release.tmp.XXXXXX"' \
  'operator_policy_durably_replace_release_ledger "$ANCHOR_MANIFEST_TEMP_PATH" "$MANIFEST_PATH"'; do
  if ! grep -Fq "$ledger_boundary" "$HELPER" "$MANIFEST_FILTER"; then
    echo "Execution-policy anchor ledger boundary is missing: $ledger_boundary" >&2
    exit 1
  fi
done
if grep -Eq 'freshDeployment\.contractSuite\.(operatorPolicyPacketSha256|operatorPolicyAuthoritySha256|reviewEnvelopeSha256|finalAuthoritySha256)' "$HELPER" "$MANIFEST_FILTER"; then
  echo "The post-CVM anchor ceremony must not claim its review envelope or final authority existed at deployment time." >&2
  exit 1
fi
if grep -Eq 'OPERATOR_POLICY_(PACKET_SHA256|AUTHORITY_SHA256)|latestReleaseOperatorPolicy(Packet|Authority)|operatorPolicy(Packet|Authority)Sha256' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Execution-policy ceremony evidence uses obsolete undifferentiated packet/authority names." >&2
  exit 1
fi
if [ "$(grep -Ec '^[[:space:]]*validate_existing_deployment_ledger$' "$HELPER")" -ne 3 ]; then
  echo "Deployment ledger must be checked before wallet access and immediately before and after the broadcast/post-state boundary." >&2
  exit 1
fi
dry_exit_line="$(grep -n -m1 'Dry run complete; no chain state changed' "$HELPER" | cut -d: -f1)"
manifest_temp_line="$(grep -n -m1 'ANCHOR_MANIFEST_TEMP_PATH=.*mktemp' "$HELPER" | cut -d: -f1)"
if [ "$dry_exit_line" -ge "$manifest_temp_line" ]; then
  echo "Dry runs must exit before creating or replacing deployment-ledger files." >&2
  exit 1
fi
for boundary in \
  'RELEASE_SHA must equal the exact lowercase checked-out commit' \
  'Refusing policy-anchor governance broadcast from a dirty source tree' \
  'RPC chainId $live_chain_id is not Base Sepolia' \
  'runtime code does not match the reviewed release hash' \
  'operator does not own anchor' \
  'anchor already contains decisions' \
  'anchor must remain paused during release admission'; do
  if ! grep -Fq "$boundary" "$HELPER" "$SCRIPT"; then
    echo "Execution-policy anchor release boundary is missing: $boundary" >&2
    exit 1
  fi
done
for phase_call in \
  'anchor.proposeWriter(inputs.writer, inputs.writerReleaseCommitment)' \
  'anchor.activateWriter()' \
  'anchor.freezeWriterRotations()' \
  'anchor.setPaused(false)'; do
  if ! grep -Fq "$phase_call" "$SCRIPT"; then
    echo "Execution-policy anchor release phase call is missing: $phase_call" >&2
    exit 1
  fi
done

ANCHOR_ADDRESS=0x1212121212121212121212121212121212121212
RUNTIME_CODE_HASH=0xabababababababababababababababababababababababababababababababab
SOURCE_COMMIT=1111111111111111111111111111111111111111
REVIEW_ENVELOPE_SHA256=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
PHASE_TWO_REVIEW_ENVELOPE_SHA256=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
FINAL_AUTHORITY_SHA256=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
RELEASE_WRITER=0x3434343434343434343434343434343434343434
RELEASE_COMMITMENT=0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
PHASE_ONE_TX=0x0101010101010101010101010101010101010101010101010101010101010101
PHASE_TWO_TX=0x0202020202020202020202020202020202020202020202020202020202020202

fixture="$TEST_TMP_DIR/ledger.json"
phase_one="$TEST_TMP_DIR/phase-one.json"
phase_two="$TEST_TMP_DIR/phase-two.json"
jq -n \
  --arg address "$ANCHOR_ADDRESS" \
  --arg runtime "$RUNTIME_CODE_HASH" \
  --arg source "$SOURCE_COMMIT" \
  '{
    schemaVersion: 2,
    network: {name: "Base Sepolia", chainId: 84532, preservedNetworkField: true},
    contracts: {
      executionPolicyAnchor: {
        address: $address,
        runtimeCodeHash: $runtime,
        sourceCommit: $source,
        deploymentTx: "preserve-deployment-transaction",
        nestedEvidence: {preserve: true},
        writer: "pre-merge-value"
      },
      unrelatedContract: {preserve: true}
    },
    freshDeployment: {
      contractSuite: {
        sourceCommit: $source,
        deploymentIntentSha256: "sha256:deployment-intent-is-unrelated"
      }
    },
    phala: {preserve: {deeply: true}},
    unrelatedTopLevel: ["keep", "every", "item"]
  }' > "$fixture"

merge_anchor_phase() {
  local input="$1"
  local output="$2"
  local phase="$3"
  local tx="$4"
  local block="$5"
  local writer="$6"
  local writer_release="$7"
  local pending_writer="$8"
  local pending_release="$9"
  local pending_at="${10}"
  local frozen="${11}"
  local paused="${12}"
  local status policy_state
  if [ "$phase" = "1" ]; then
    status=deployed_paused_exact_writer_release_pending_timelock
    policy_state=anchoring_fail_closed_exact_writer_release_pending_timelock
  else
    status=deployed_active_exact_writer_release_frozen
    policy_state=anchoring_enabled_exact_writer_release_frozen
  fi
  jq \
    --argjson chainId 84532 \
    --arg anchorAddress "$ANCHOR_ADDRESS" \
    --arg runtimeCodeHash "$RUNTIME_CODE_HASH" \
    --arg sourceCommit "$SOURCE_COMMIT" \
    --arg reviewEnvelopeSha256 "$REVIEW_ENVELOPE_SHA256" \
    --arg finalAuthoritySha256 "$FINAL_AUTHORITY_SHA256" \
    --argjson phase "$phase" \
    --arg transactionHash "$tx" \
    --argjson blockNumber "$block" \
    --argjson blockTimestamp 1784637296 \
    --arg recordedAt "2026-07-21T12:34:56Z" \
    --arg status "$status" \
    --arg policyState "$policy_state" \
    --arg releaseWriter "$RELEASE_WRITER" \
    --arg releaseCommitment "$RELEASE_COMMITMENT" \
    --arg writer "$writer" \
    --arg writerReleaseCommitment "$writer_release" \
    --arg pendingWriter "$pending_writer" \
    --arg pendingWriterReleaseCommitment "$pending_release" \
    --argjson pendingWriterActivatesAt "$pending_at" \
    --argjson writerRotationsFrozen "$frozen" \
    --argjson paused "$paused" \
    --argjson globalSequence 0 \
    --arg globalHead "$ZERO_BYTES32" \
    -f "$MANIFEST_FILTER" \
    "$input" > "$output"
}

merge_anchor_phase \
  "$fixture" "$phase_one" 1 "$PHASE_ONE_TX" 12345 \
  "$ZERO_ADDRESS" "$ZERO_BYTES32" "$RELEASE_WRITER" "$RELEASE_COMMITMENT" 1730000000 false true

jq -e \
  --arg address "$ANCHOR_ADDRESS" \
  --arg runtime "$RUNTIME_CODE_HASH" \
  --arg source "$SOURCE_COMMIT" \
  --arg writer "$RELEASE_WRITER" \
  --arg release "$RELEASE_COMMITMENT" \
  --arg tx "$PHASE_ONE_TX" \
  --arg review "$REVIEW_ENVELOPE_SHA256" \
  --arg authority "$FINAL_AUTHORITY_SHA256" \
  '
    .schemaVersion == 2
    and .network.preservedNetworkField == true
    and .contracts.unrelatedContract.preserve == true
    and .contracts.executionPolicyAnchor.deploymentTx == "preserve-deployment-transaction"
    and .contracts.executionPolicyAnchor.nestedEvidence.preserve == true
    and .phala.preserve.deeply == true
    and .unrelatedTopLevel == ["keep", "every", "item"]
    and .contracts.executionPolicyAnchor.address == $address
    and .contracts.executionPolicyAnchor.runtimeCodeHash == $runtime
    and .contracts.executionPolicyAnchor.sourceCommit == $source
    and .contracts.executionPolicyAnchor.writer == "0x0000000000000000000000000000000000000000"
    and .contracts.executionPolicyAnchor.pendingWriter == $writer
    and .contracts.executionPolicyAnchor.pendingWriterReleaseCommitment == $release
    and .contracts.executionPolicyAnchor.writerRotationsFrozen == false
    and .contracts.executionPolicyAnchor.paused == true
    and .contracts.executionPolicyAnchor.globalSequence == 0
    and .contracts.executionPolicyAnchor.globalHead == "0x0000000000000000000000000000000000000000000000000000000000000000"
    and .contracts.executionPolicyAnchor.latestReleaseReviewEnvelopeSha256 == $review
    and .contracts.executionPolicyAnchor.latestReleaseFinalAuthoritySha256 == $authority
    and (.executionPolicyAnchorReleaseHistory | length) == 1
    and .executionPolicyAnchorReleaseHistory[0].chainId == 84532
    and .executionPolicyAnchorReleaseHistory[0].executionPolicyAnchorAddress == $address
    and .executionPolicyAnchorReleaseHistory[0].runtimeCodeHash == $runtime
    and .executionPolicyAnchorReleaseHistory[0].sourceCommit == $source
    and .executionPolicyAnchorReleaseHistory[0].phase == 1
    and .executionPolicyAnchorReleaseHistory[0].transactionHash == $tx
    and .executionPolicyAnchorReleaseHistory[0].blockNumber == 12345
    and .executionPolicyAnchorReleaseHistory[0].blockTimestamp == 1784637296
    and .executionPolicyAnchorReleaseHistory[0].recordedAt == "2026-07-21T12:34:56Z"
    and .executionPolicyAnchorReleaseHistory[0].reviewEnvelopeSha256 == $review
    and .executionPolicyAnchorReleaseHistory[0].finalAuthoritySha256 == $authority
  ' "$phase_one" >/dev/null

REVIEW_ENVELOPE_SHA256="$PHASE_TWO_REVIEW_ENVELOPE_SHA256"
merge_anchor_phase \
  "$phase_one" "$phase_two" 2 "$PHASE_TWO_TX" 12346 \
  "$RELEASE_WRITER" "$RELEASE_COMMITMENT" "$ZERO_ADDRESS" "$ZERO_BYTES32" 0 true false

jq -e \
  --arg writer "$RELEASE_WRITER" \
  --arg release "$RELEASE_COMMITMENT" \
  --arg tx "$PHASE_TWO_TX" \
  --arg phaseOneReview "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --arg phaseTwoReview "$PHASE_TWO_REVIEW_ENVELOPE_SHA256" \
  --arg authority "$FINAL_AUTHORITY_SHA256" \
  '
    .contracts.executionPolicyAnchor.writer == $writer
    and .contracts.executionPolicyAnchor.writerReleaseCommitment == $release
    and .contracts.executionPolicyAnchor.pendingWriter == "0x0000000000000000000000000000000000000000"
    and .contracts.executionPolicyAnchor.pendingWriterReleaseCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
    and .contracts.executionPolicyAnchor.pendingWriterActivatesAt == 0
    and .contracts.executionPolicyAnchor.writerRotationsFrozen == true
    and .contracts.executionPolicyAnchor.paused == false
    and .contracts.executionPolicyAnchor.latestReleasePhase == 2
    and .contracts.executionPolicyAnchor.latestReleaseReviewEnvelopeSha256 == $phaseTwoReview
    and .contracts.executionPolicyAnchor.latestReleaseFinalAuthoritySha256 == $authority
    and (.executionPolicyAnchorReleaseHistory | map(.phase)) == [1, 2]
    and (.executionPolicyAnchorReleaseHistory | map(.reviewEnvelopeSha256)) == [$phaseOneReview, $phaseTwoReview]
    and (.executionPolicyAnchorReleaseHistory | map(.finalAuthoritySha256) | unique) == [$authority]
    and .executionPolicyAnchorReleaseHistory[1].transactionHash == $tx
    and .phala.preserve.deeply == true
  ' "$phase_two" >/dev/null

for mismatch in address runtime source; do
  mismatched="$TEST_TMP_DIR/mismatch-$mismatch.json"
  case "$mismatch" in
    address) jq '.contracts.executionPolicyAnchor.address = "0x9999999999999999999999999999999999999999"' "$fixture" > "$mismatched" ;;
    runtime) jq '.contracts.executionPolicyAnchor.runtimeCodeHash = ("0x" + ("99" * 32))' "$fixture" > "$mismatched" ;;
    source) jq '.contracts.executionPolicyAnchor.sourceCommit = ("9" * 40)' "$fixture" > "$mismatched" ;;
  esac
  if merge_anchor_phase \
    "$mismatched" "$TEST_TMP_DIR/unexpected-$mismatch.json" 1 "$PHASE_ONE_TX" 12345 \
    "$ZERO_ADDRESS" "$ZERO_BYTES32" "$RELEASE_WRITER" "$RELEASE_COMMITMENT" 1730000000 false true 2>/dev/null; then
    echo "Execution-policy ledger merge accepted a mismatched $mismatch." >&2
    exit 1
  fi
done

if merge_anchor_phase \
  "$fixture" "$TEST_TMP_DIR/out-of-order.json" 2 "$PHASE_TWO_TX" 12346 \
  "$RELEASE_WRITER" "$RELEASE_COMMITMENT" "$ZERO_ADDRESS" "$ZERO_BYTES32" 0 true false 2>/dev/null; then
  echo "Execution-policy ledger merge accepted phase 2 without phase 1 evidence." >&2
  exit 1
fi

echo "execution-policy anchor release helper safety checks passed"
