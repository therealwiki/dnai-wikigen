#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
HELPER="$SCRIPT_DIR/configure-challenge-registry-release.sh"
MANIFEST_FILTER="$SCRIPT_DIR/update-challenge-registry-release-manifest.jq"
SCRIPT="$SCRIPT_DIR/../script/ConfigureChallengeRegistryRelease.s.sol"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"
PROJECTOR="$ROOT_DIR/scripts/challenge-registry-authority-projector.mjs"

bash -n "$HELPER"
bash -n "$POLICY_GUARD"
test -s "$MANIFEST_FILTER"
test -s "$SCRIPT"
test -s "$PROJECTOR"

for boundary in \
  'operator_policy_project_and_validate' \
  'challenge-registry-authority-projector.mjs' \
  'dnai.challenge-registry-authority-projection.v1' \
  'FINAL_RELEASE_AUTHORITY_CORE_PATH' \
  'OPERATOR_POLICY_FINAL_AUTHORITY_SHA256' \
  'OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256' \
  'ChallengeRegistry authority projector returned a malformed, incomplete, or mismatched catalog' \
  'Phase 1 requires the exact pristine ChallengeRegistry with next ID 1' \
  'version review timelock has not elapsed' \
  'Mined ChallengeRegistry transaction' \
  'Deployment ledger changed while the ChallengeRegistry release was broadcasting' \
  'challengeRegistryReleaseHistory' \
  'operator_policy_acquire_release_ceremony_lock challenge_registry_release' \
  'operator_policy_durably_replace_release_ledger' \
  'operator_policy_release_release_ceremony_lock' \
  'wait_for_finalized_receipts' \
  'latestReleaseStateBlockHash' \
  'FOUNDRY_BROADCAST must remain outside the reviewed source repository' \
  'git hash-object --no-filters' \
  'mktemp "$manifest_dir/.${manifest_base}.challenge-registry-release.XXXXXX"'; do
  if ! grep -Fq "$boundary" "$HELPER" "$MANIFEST_FILTER" "$SCRIPT"; then
    echo "ChallengeRegistry release safety boundary is missing: $boundary" >&2
    exit 1
  fi
done

for phase_call in \
  'registry.createChallenge(' \
  'inputs.registry.freezeChallengeConfiguration(challengeId)' \
  'inputs.registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Open)'; do
  grep -Fq "$phase_call" "$SCRIPT"
done

if grep -q -- '--private-key' "$HELPER"; then
  echo "ChallengeRegistry release helper must never accept raw private keys." >&2
  exit 1
fi
grep -q -- '--account dev' "$HELPER"
grep -Fq 'ChallengeRegistry release is Base Sepolia only' "$SCRIPT"
grep -Fq 'RPC chainId $live_chain_id is not Base Sepolia' "$HELPER"
grep -Fq 'runtime code does not match the reviewed release hash' "$HELPER"
grep -Fq 'operator does not own ChallengeRegistry' "$SCRIPT"
grep -Fq 'DEPLOYMENT_OPERATOR is not the live ChallengeRegistry owner' "$HELPER"
grep -Fq 'cast decode-calldata' "$HELPER"
grep -Fq 'cast tx "$tx_hash" input' "$HELPER"
grep -Fq 'RUN_PATH="$FOUNDRY_BROADCAST/ConfigureChallengeRegistryRelease.s.sol/$CHAIN_ID/run-latest.json"' "$HELPER"
grep -Fq -- '--block "$state_block"' "$HELPER"
grep -Fq 'cast block finalized --field number' "$HELPER"
grep -Fq -- '--arg stateBlockHash "$OBSERVED_STATE_BLOCK_HASH"' "$HELPER"
grep -Fq '"blockHash"' "$MANIFEST_FILTER"
if [ "$(grep -Ec '^[[:space:]]*revalidate_release_authority_and_catalog$' "$HELPER")" -lt 2 ]; then
  echo "ChallengeRegistry helper must renew authority/review validation after unlock and before broadcast." >&2
  exit 1
fi

if [ "$(grep -Ec '^[[:space:]]*check_release_provenance$' "$HELPER")" -lt 3 ]; then
  echo "ChallengeRegistry helper must repeat clean-source provenance checks around unlock and broadcast." >&2
  exit 1
fi
policy_line="$(grep -n -m1 '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER" | cut -d: -f1)"
wallet_line="$(grep -n -m1 'cast wallet list' "$HELPER" | cut -d: -f1)"
dry_line="$(grep -n -m1 '^forge script' "$HELPER" | cut -d: -f1)"
if [ "$policy_line" -ge "$wallet_line" ] || [ "$policy_line" -ge "$dry_line" ]; then
  echo "ChallengeRegistry authority validation must precede wallet access and simulation." >&2
  exit 1
fi
dry_exit_line="$(grep -n -m1 '^if \[ "\$BROADCAST" != "true" \]; then' "$HELPER" | cut -d: -f1)"
temp_line="$(grep -n -m1 'CHALLENGE_REGISTRY_MANIFEST_TEMP_PATH="\$(mktemp' "$HELPER" | cut -d: -f1)"
publish_line="$(grep -n -m1 '^operator_policy_durably_replace_release_ledger' "$HELPER" | cut -d: -f1)"
lock_line="$(grep -n -m1 '^operator_policy_acquire_release_ceremony_lock challenge_registry_release$' "$HELPER" | cut -d: -f1)"
release_line="$(grep -n -m1 '^operator_policy_release_release_ceremony_lock$' "$HELPER" | cut -d: -f1)"
unlock_line="$(grep -n -m1 'cast wallet address --account dev' "$HELPER" | cut -d: -f1)"
if [ -z "$dry_exit_line" ] || [ -z "$temp_line" ] || [ -z "$publish_line" ] \
  || [ -z "$lock_line" ] || [ -z "$release_line" ] || [ -z "$unlock_line" ] \
  || [ "$lock_line" -le "$dry_exit_line" ] || [ "$temp_line" -le "$dry_exit_line" ] \
  || [ "$unlock_line" -le "$lock_line" ] || [ "$publish_line" -le "$temp_line" ] \
  || [ "$release_line" -le "$publish_line" ]; then
  echo "Dry runs must exit before ChallengeRegistry ledger temporary files or replacement." >&2
  exit 1
fi
if [ "$(grep -Ec '^operator_policy_release_release_ceremony_lock$' "$HELPER")" -ne 1 ]; then
  echo "ChallengeRegistry lock must release exactly once, only after durable publication." >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])eval[[:space:]]|^[[:space:]]*(source|\.)[[:space:]]+.*CATALOG' "$HELPER"; then
  echo "ChallengeRegistry catalog projection must remain inert JSON." >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])(cp|cat)[[:space:]].*MANIFEST_PATH|>[[:space:]]*"?\$MANIFEST_PATH' "$HELPER"; then
  echo "ChallengeRegistry ledger must only be replaced from a validated same-directory temporary file." >&2
  exit 1
fi
if grep -Eq 'CHALLENGE_REGISTRY_LEDGER_LOCK_|acquire_deployment_ledger_lock|mv -f -- .*MANIFEST_PATH' "$HELPER"; then
  echo "ChallengeRegistry helper must use only the release-wide lock and durable publication API." >&2
  exit 1
fi
if grep -Eq 'freshDeployment\.contractSuite\.(finalAuthority|reviewEnvelope|challengeRegistryRelease)' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Post-authority ChallengeRegistry evidence must not be backdated into fresh deployment." >&2
  exit 1
fi

node --test "$ROOT_DIR/scripts/challenge-registry-authority-projector.test.mjs"

fixture_dir="$(mktemp -d)"
trap 'rm -rf -- "$fixture_dir"' EXIT
fixture="$fixture_dir/ledger.json"
phase_one="$fixture_dir/phase-one.json"
phase_two="$fixture_dir/phase-two.json"

registry=0x1111111111111111111111111111111111111111
operator=0x2222222222222222222222222222222222222222
runtime=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=0123456789abcdef0123456789abcdef01234567
review=sha256:abababababababababababababababababababababababababababababababab
authority=sha256:bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc
projection_sha=sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
controller=0x3333333333333333333333333333333333333333
metadata=0x1111111111111111111111111111111111111111111111111111111111111111
sealed=0x2222222222222222222222222222222222222222222222222222222222222222
evaluator=0x3333333333333333333333333333333333333333333333333333333333333333
release=0x4444444444444444444444444444444444444444444444444444444444444444

catalog="$(jq -nc \
  --arg source "$source_commit" \
  --arg authority "$authority" \
  --arg registry "$registry" \
  --arg runtime "$runtime" \
  --arg operator "$operator" \
  --arg controller "$controller" \
  --arg metadata "$metadata" \
  --arg sealed "$sealed" \
  --arg evaluator "$evaluator" \
  --arg release "$release" '
  {
    schema: "dnai.challenge-registry-authority-projection.v1",
    releaseSha: $source,
    chainId: 84532,
    finalAuthoritySha256: $authority,
    registry: {
      address: $registry,
      runtimeCodeHash: $runtime,
      owner: $operator,
      pendingOwner: "0x0000000000000000000000000000000000000000",
      registryPaused: false,
      minimumVersionReviewDelaySeconds: 172800,
      expectedChallengeCount: 1
    },
    entries: [{
      catalogKey: "bio-qc@1.0.0",
      challengeId: 1,
      version: 1,
      controller: $controller,
      pendingController: "0x0000000000000000000000000000000000000000",
      lifecycle: "open",
      paused: false,
      configurationFrozen: true,
      catalogManifestHash: $metadata,
      metadataURI: "ipfs://arena/bio-qc",
      metadataHash: $metadata,
      sealedArtifactCommitment: $sealed,
      evaluatorCommitment: $evaluator,
      releasePolicyCommitment: $release
    }]
  }')"

observed() {
  local lifecycle="$1"
  local frozen="$2"
  local updated="$3"
  jq -nc \
    --arg controller "$controller" \
    --arg lifecycle "$lifecycle" \
    --argjson frozen "$frozen" \
    --argjson updated "$updated" \
    --arg metadata "$metadata" \
    --arg sealed "$sealed" \
    --arg evaluator "$evaluator" \
    --arg release "$release" '
    [{
      catalogKey: "bio-qc@1.0.0", challengeId: 1,
      controller: $controller,
      pendingController: "0x0000000000000000000000000000000000000000",
      lifecycle: $lifecycle, createdAt: 100, updatedAt: $updated,
      latestVersion: 1, paused: false, configurationFrozen: $frozen,
      controllerPaused: false, governancePaused: false,
      reviewEligibleAt: 172900,
      metadataURI: "ipfs://arena/bio-qc", metadataHash: $metadata,
      sealedArtifactCommitment: $sealed, evaluatorCommitment: $evaluator,
      releasePolicyCommitment: $release
    }]'
}

phase_one_receipts='[{"transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","calldataHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","function":"createChallenge","challengeId":1,"blockHash":"0x1010101010101010101010101010101010101010101010101010101010101010","blockNumber":101,"blockTimestamp":100,"transactionIndex":0}]'
phase_two_receipts='[{"transactionHash":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","calldataHash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","function":"freezeChallengeConfiguration","challengeId":1,"blockHash":"0x2020202020202020202020202020202020202020202020202020202020202020","blockNumber":201,"blockTimestamp":172900,"transactionIndex":0},{"transactionHash":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","calldataHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","function":"setLifecycleOpen","challengeId":1,"blockHash":"0x3030303030303030303030303030303030303030303030303030303030303030","blockNumber":202,"blockTimestamp":172901,"transactionIndex":0}]'

jq -n \
  --arg registry "$registry" --arg runtime "$runtime" --arg source "$source_commit" '
  {
    schemaVersion: 2,
    network: {chainId: 84532, preserve: true},
    contracts: {
      challengeRegistry: {
        address: $registry, runtimeCodeHash: $runtime, sourceCommit: $source,
        deploymentTx: "preserve-deployment-transaction", nested: {preserve: true}
      },
      unrelated: {preserve: true}
    },
    freshDeployment: {contractSuite: {sourceCommit: $source, preserve: true}},
    phala: {deep: {preserve: true}},
    unrelatedTopLevel: ["preserve"]
  }' > "$fixture"

apply_phase() {
  local input="$1"
  local output="$2"
  local phase="$3"
  local observed_json="$4"
  local receipts="$5"
  local status policy
  local state_block state_hash state_timestamp latest_block latest_hash latest_timestamp
  if [ "$phase" = "1" ]; then
    status=deployed_exact_arena_genesis_pending_version_review
    policy=arena_genesis_fail_closed_pending_two_day_version_review
    state_block=150
    state_hash=0x1515151515151515151515151515151515151515151515151515151515151515
    state_timestamp=100
    latest_block=151
    latest_hash=0x1616161616161616161616161616161616161616161616161616161616161616
    latest_timestamp=100
  else
    status=deployed_exact_arena_genesis_frozen_open
    policy=arena_genesis_exact_version_one_catalog_frozen_open
    state_block=300
    state_hash=0x3535353535353535353535353535353535353535353535353535353535353535
    state_timestamp=172902
    latest_block=301
    latest_hash=0x3636363636363636363636363636363636363636363636363636363636363636
    latest_timestamp=172902
  fi
  jq \
    --argjson chainId 84532 \
    --arg registryAddress "$registry" \
    --arg runtimeCodeHash "$runtime" \
    --arg operator "$operator" \
    --arg sourceCommit "$source_commit" \
    --arg reviewEnvelopeSha256 "$review" \
    --arg finalAuthoritySha256 "$authority" \
    --arg catalogProjectionSha256 "$projection_sha" \
    --argjson phase "$phase" \
    --arg recordedAt "2026-07-21T12:00:0${phase}Z" \
    --arg status "$status" \
    --arg policyState "$policy" \
    --argjson stateBlockNumber "$state_block" \
    --arg stateBlockHash "$state_hash" \
    --argjson stateBlockTimestamp "$state_timestamp" \
    --argjson latestCheckBlockNumber "$latest_block" \
    --arg latestCheckBlockHash "$latest_hash" \
    --argjson latestCheckBlockTimestamp "$latest_timestamp" \
    --argjson catalog "$catalog" \
    --argjson observedCatalog "$observed_json" \
    --argjson transactionReceipts "$receipts" \
    -f "$MANIFEST_FILTER" "$input" > "$output"
}

apply_phase "$fixture" "$phase_one" 1 "$(observed draft false 100)" "$phase_one_receipts"
phase_one_review="$review"
review="sha256:$(printf 'de%.0s' {1..32})"
apply_phase "$phase_one" "$phase_two" 2 "$(observed open true 172901)" "$phase_two_receipts"

jq -e \
  --arg registry "$registry" \
  --arg authority "$authority" \
  --arg review "$review" \
  --arg phaseOneReview "$phase_one_review" '
    .schemaVersion == 2
    and .network.preserve == true
    and .contracts.unrelated.preserve == true
    and .contracts.challengeRegistry.deploymentTx == "preserve-deployment-transaction"
    and .contracts.challengeRegistry.nested.preserve == true
    and .freshDeployment.contractSuite.preserve == true
    and .phala.deep.preserve == true
    and .unrelatedTopLevel == ["preserve"]
    and .contracts.challengeRegistry.address == $registry
    and .contracts.challengeRegistry.challengeCount == 1
    and .contracts.challengeRegistry.nextChallengeId == 2
    and .contracts.challengeRegistry.latestReleasePhase == 2
    and .contracts.challengeRegistry.genesisCatalog[0].lifecycle == "open"
    and .contracts.challengeRegistry.genesisCatalog[0].configurationFrozen == true
    and .contracts.challengeRegistry.latestReleaseFinalAuthoritySha256 == $authority
    and .contracts.challengeRegistry.latestReleaseReviewEnvelopeSha256 == $review
    and (.challengeRegistryReleaseHistory | map(.phase)) == [1, 2]
    and (.challengeRegistryReleaseHistory | map(.finalAuthoritySha256) | unique) == [$authority]
    and (.challengeRegistryReleaseHistory | map(.reviewEnvelopeSha256)) == [$phaseOneReview, $review]
    and (.challengeRegistryReleaseHistory[0].transactionReceipts | length) == 1
    and (.challengeRegistryReleaseHistory[1].transactionReceipts | length) == 2
  ' "$phase_two" >/dev/null

if apply_phase "$fixture" "$fixture_dir/skip.json" 2 "$(observed open true 172901)" "$phase_two_receipts" 2>/dev/null; then
  echo "ChallengeRegistry manifest accepted phase 2 without phase 1." >&2
  exit 1
fi
if apply_phase "$phase_one" "$fixture_dir/replay.json" 1 "$(observed draft false 100)" "$phase_one_receipts" 2>/dev/null; then
  echo "ChallengeRegistry manifest accepted a replayed phase 1." >&2
  exit 1
fi

bad_catalog="$(jq -c '.entries[0].challengeId = 2' <<<"$catalog")"
saved_catalog="$catalog"
catalog="$bad_catalog"
if apply_phase "$fixture" "$fixture_dir/noncontiguous.json" 1 "$(observed draft false 100)" "$phase_one_receipts" 2>/dev/null; then
  echo "ChallengeRegistry manifest accepted a noncontiguous catalog." >&2
  exit 1
fi
catalog="$saved_catalog"

bad_observed="$(observed draft false 100 | jq -c '.[0].metadataHash = ("0x" + ("99" * 32))')"
if apply_phase "$fixture" "$fixture_dir/drift.json" 1 "$bad_observed" "$phase_one_receipts" 2>/dev/null; then
  echo "ChallengeRegistry manifest accepted observed version drift." >&2
  exit 1
fi

duplicate_receipts="$(jq -c '.[1] = .[0]' <<<"$phase_two_receipts")"
if apply_phase "$phase_one" "$fixture_dir/duplicate.json" 2 "$(observed open true 172901)" "$duplicate_receipts" 2>/dev/null; then
  echo "ChallengeRegistry manifest accepted duplicate transaction receipts." >&2
  exit 1
fi

missing_block_hash="$(jq -c '.[0] |= del(.blockHash)' <<<"$phase_one_receipts")"
if apply_phase "$fixture" "$fixture_dir/missing-block-hash.json" 1 "$(observed draft false 100)" "$missing_block_hash" 2>/dev/null; then
  echo "ChallengeRegistry manifest accepted receipt evidence without a canonical block hash." >&2
  exit 1
fi

reordered_receipts="$(jq -c '.[1].blockNumber = 200' <<<"$phase_two_receipts")"
if apply_phase "$phase_one" "$fixture_dir/reordered.json" 2 "$(observed open true 172901)" "$reordered_receipts" 2>/dev/null; then
  echo "ChallengeRegistry manifest accepted receipts that do not occur in chain order." >&2
  exit 1
fi

echo "ChallengeRegistry release helper safety checks passed"
