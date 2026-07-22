#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/configure-tinker-release.sh"
MANIFEST_FILTER="$SCRIPT_DIR/update-tinker-release-manifest.jq"
LEGACY_APPROVAL_HELPER="$SCRIPT_DIR/../../scripts/approve-compose-hash.sh"
SCRIPT="$SCRIPT_DIR/../script/ConfigureTinkerRelease.s.sol"
CONTRACT="$SCRIPT_DIR/../src/TinkerAccountEncumbrance.sol"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"

bash -n "$HELPER"
bash -n "$POLICY_GUARD"
bash -n "$LEGACY_APPROVAL_HELPER"

for guard_boundary in \
  'ceremony-authority-projector.mjs' \
  'dnai.ceremony-authority-projection.v1' \
  '.assertionCount == 31' \
  'Legacy OPERATOR_POLICY_PACKET_* inputs are retired and rejected' \
  'OPERATOR_POLICY_PROJECTION_PATH is rejected; ceremony values are derived by the code-owned cryptographic projector'; do
  if ! grep -Fq "$guard_boundary" "$POLICY_GUARD"; then
    echo "Shared Tinker authority guard is missing fail-closed boundary: $guard_boundary" >&2
    exit 1
  fi
done
if grep -Eq 'operator-policy-packet\.mjs.*[[:space:]]project([[:space:]]|$)' "$POLICY_GUARD"; then
  echo "Tinker authority guard must never call the retired packet projector." >&2
  exit 1
fi

grep -Fq '. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"' "$HELPER"
test "$(grep -Ec '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER")" -eq 1
for ceremony_digest in \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256; do
  if ! grep -Fq "$ceremony_digest" "$HELPER"; then
    echo "Tinker release is missing exact ceremony digest: $ceremony_digest" >&2
    exit 1
  fi
done
if grep -Eq 'OPERATOR_POLICY_PACKET|latestReleaseOperatorPolicy|operatorPolicy(Packet|Authority)Sha256' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Tinker release evidence must use finalAuthoritySha256 and reviewEnvelopeSha256 names." >&2
  exit 1
fi
policy_line="$(grep -n -m1 '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER" | cut -d: -f1)"
wallet_line="$(grep -n -m1 'cast wallet list' "$HELPER" | cut -d: -f1)"
first_cast_line="$(grep -n -m1 '^live_chain_id=.*cast chain-id' "$HELPER" | cut -d: -f1)"
dry_run_line="$(grep -n -m1 '^forge script' "$HELPER" | cut -d: -f1)"
if [ "$policy_line" -ge "$wallet_line" ] \
  || [ "$policy_line" -ge "$first_cast_line" ] \
  || [ "$policy_line" -ge "$dry_run_line" ]; then
  echo "Tinker operator policy must fail closed before wallet, chain, or simulation access." >&2
  exit 1
fi
for policy_env in \
  TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT \
  TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI \
  TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI \
  TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH \
  TINKER_ENCUMBRANCE_RELEASE_MANAGER; do
  grep -Fq "$policy_env" "$HELPER"
done
grep -Fq 'operator_policy_assert_public_env postDeployEnv "$policy_env_name"' "$HELPER"
grep -Fq 'validate_nonzero_address TINKER_ENCUMBRANCE_RELEASE_MANAGER' "$HELPER"
grep -Fq 'manager_array="[$TINKER_ENCUMBRANCE_RELEASE_MANAGER]"' "$HELPER"
grep -Fq 'expected_manager_count=1' "$HELPER"
grep -Fq 'empty_compose_root=' "$HELPER"
grep -Fq 'approvedComposeHashes: (if $composeCount == 0 then [] else [$composeHash] end)' "$MANIFEST_FILTER"
if grep -Fq 'approvedComposeHashAt' "$HELPER"; then
  echo "Fresh Tinker release must begin with empty compose authority." >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])eval[[:space:]]|^[[:space:]]*(source|\.)[[:space:]]+.*OPERATOR_POLICY_PROJECTION' "$POLICY_GUARD" "$HELPER"; then
  echo "Tinker release must never evaluate or source operator-policy projection JSON." >&2
  exit 1
fi

if grep -Eq 'approveComposeHash|cast[[:space:]]+send' "$LEGACY_APPROVAL_HELPER"; then
  echo "Legacy compose helper must never advertise or send a mutable compose addition." >&2
  exit 1
fi
if ! grep -Fq 'configure-tinker-release.sh' "$LEGACY_APPROVAL_HELPER"; then
  echo "Legacy compose helper must direct operators to the exact release ceremony." >&2
  exit 1
fi

if grep -q -- '--private-key' "$HELPER"; then
  echo "Tinker release helper must never accept raw private keys." >&2
  exit 1
fi
if ! grep -q -- '--account dev' "$HELPER"; then
  echo "Tinker release broadcasts must use the literal dev keystore account." >&2
  exit 1
fi
if [ "$(grep -Fc 'check_release_provenance' "$HELPER")" -lt 4 ]; then
  echo "Tinker release helper must check clean-source provenance before broadcast and keystore use." >&2
  exit 1
fi
if grep -Eq -- '--argjson (maxAddBalanceWei|maxSpendWei|releaseMaxAddBalanceWei|releaseMaxSpendWei|pendingMaxAddBalanceWei|pendingMaxSpendWei)' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Tinker uint256 caps must be serialized as canonical decimal strings, never jq numbers." >&2
  exit 1
fi
if grep -Fq 'releasePolicyCommitment: (if' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Tinker release commitment must remain an explicit bytes32 value in every phase." >&2
  exit 1
fi

for policy_unit_boundary in \
  'MAX_TINKER_POLICY_UNITS_PER_OPERATION=10000000000000000000' \
  'validate_tinker_policy_caps' \
  'not ETH or cumulative'; do
  if ! grep -Fq "$policy_unit_boundary" "$HELPER"; then
    echo "Tinker release helper is missing the policy-unit boundary: $policy_unit_boundary" >&2
    exit 1
  fi
done

for contract_policy_boundary in \
  'MAX_POLICY_UNITS_PER_OPERATION = 10_000_000_000_000_000_000' \
  '_validateFundingPolicy(initialMaxAddBalanceWei, initialMaxSpendWei)' \
  '_validateFundingPolicy(newMaxAddBalanceWei, newMaxSpendWei)'; do
  if ! grep -Fq "$contract_policy_boundary" "$CONTRACT"; then
    echo "Tinker contract is missing the hard policy-unit boundary: $contract_policy_boundary" >&2
    exit 1
  fi
done

if grep -Fq 'onlyOwnerOrManager' "$CONTRACT" \
  || [ "$(grep -Fc 'if (!managers[msg.sender]) revert NotManager();' "$CONTRACT")" -lt 2 ]; then
  echo "Active Tinker operation authorization and settlement must remain manager-only, with no owner fallback." >&2
  exit 1
fi

for script_policy_boundary in \
  'Tinker per-operation policy-unit caps must be nonzero' \
  'Tinker spend policy-unit cap exceeds add-balance cap' \
  'Tinker per-operation policy-unit cap exceeds hard maximum'; do
  if ! grep -Fq "$script_policy_boundary" "$SCRIPT"; then
    echo "Tinker release script is missing the policy-unit boundary: $script_policy_boundary" >&2
    exit 1
  fi
done

for boundary in \
  'TINKER_ENCUMBRANCE_RELEASE_PHASE must be exactly 1 or 2' \
  'RELEASE_SHA must equal the exact lowercase checked-out commit' \
  'Refusing Tinker governance broadcast from a dirty source tree' \
  'RPC chainId $live_chain_id is not Base Sepolia' \
  'runtime code does not match the reviewed release hash' \
  'DEPLOYMENT_OPERATOR is not the live TinkerAccountEncumbrance owner' \
  'must remain emergency halted before phase 2' \
  'pending ownership transfer blocks release' \
  'two-day Tinker release timelock has not elapsed'; do
  if ! grep -Fqi "$boundary" "$HELPER" "$SCRIPT"; then
    echo "Tinker release boundary is missing: $boundary" >&2
    exit 1
  fi
done

for exact_field in \
  'accountCommitment' \
  'maxAddBalanceWei' \
  'maxSpendWei' \
  'approvedComposeRoot' \
  'approvedComposeCount' \
  'managerRoot' \
  'managerCount' \
  'pendingReleasePolicyCommitment' \
  'pendingReleasePolicyActivatesAt' \
  'releasePolicyCommitment' \
  'releasePolicyFrozen' \
  'emergencyHalted'; do
  if ! grep -Fq "$exact_field" "$HELPER" || ! grep -Fq "$exact_field" "$SCRIPT"; then
    echo "Exact Tinker release field is not checked in both layers: $exact_field" >&2
    exit 1
  fi
done

for phase_call in \
  'encumbrance.proposeReleasePolicy(' \
  'encumbrance.activateAndFreezeReleasePolicy()'; do
  if ! grep -Fq "$phase_call" "$SCRIPT"; then
    echo "Tinker release phase call is missing: $phase_call" >&2
    exit 1
  fi
done

for monotonic_path in \
  'reduceFundingPolicy' \
  'revokeManager' \
  'revokeComposeHash' \
  'RiskIncreaseRequiresNewRelease'; do
  if ! grep -Fq "$monotonic_path" "$CONTRACT"; then
    echo "Frozen Tinker policy is missing monotonic control: $monotonic_path" >&2
    exit 1
  fi
done

for ledger_field in \
  'tinkerReleaseHistory' \
  'encumbranceAddress' \
  'runtimeCodeHash' \
  'latestReleaseSourceCommit' \
  'latestReleaseReviewEnvelopeSha256' \
  'latestReleaseFinalAuthoritySha256' \
  'reviewEnvelopeSha256' \
  'finalAuthoritySha256' \
  'pendingOwner' \
  'perOperationCaps: true' \
  'custodiesFunds: false' \
  'approvedComposeHashes' \
  'managers' \
  'composeRoot' \
  'managerRoot' \
  'releasePolicyCommitment' \
  'releaseMaxAddBalanceWei' \
  'releaseMaxSpendWei' \
  'releaseComposeHashes' \
  'releaseComposeRoot' \
  'releaseComposeCount' \
  'releaseManagers' \
  'releaseManagerRoot' \
  'releaseManagerCount' \
  'pendingAccountCommitment' \
  'pendingMaxAddBalanceWei' \
  'pendingMaxSpendWei' \
  'pendingComposeHashes' \
  'pendingComposeRoot' \
  'pendingComposeCount' \
  'pendingManagers' \
  'pendingManagerRoot' \
  'pendingManagerCount' \
  'transactionHash' \
  'blockNumber'; do
  if ! grep -Fq "$ledger_field" "$HELPER" "$MANIFEST_FILTER"; then
    echo "Tinker append-only release evidence is missing: $ledger_field" >&2
    exit 1
  fi
done

fixture_input="$(mktemp)"
fixture_output="$(mktemp)"
trap 'rm -f "$fixture_input" "$fixture_output"' EXIT
jq -n '{
  contracts: {tinkerAccountEncumbrance: {sourceCommit: "deployment-source-commit"}},
  tinkerReleaseHistory: [{
    kind: "tinker_exact_release_policy_phase",
    chainId: 84532,
    encumbranceAddress: "0x2222222222222222222222222222222222222222",
    runtimeCodeHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    sourceCommit: "0123456789abcdef0123456789abcdef01234567",
    reviewEnvelopeSha256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    finalAuthoritySha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    phase: 1
  }]
}' > "$fixture_input"
jq \
  --arg status "deployed_exact_release_policy_frozen_active" \
  --arg encumbranceAddress "0x1111111111111111111111111111111111111111" \
  --arg runtimeCodeHash "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --argjson phase 2 \
  --arg tx "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --argjson block 123 \
  --arg recordedAt "2026-01-01T00:00:00Z" \
  --arg sourceCommit "0123456789abcdef0123456789abcdef01234567" \
  --arg reviewEnvelopeSha256 "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  --arg finalAuthoritySha256 "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --arg policyState "exact_timelocked_release_policy_frozen_active" \
  --arg pendingOwner "0x0000000000000000000000000000000000000000" \
  --arg accountCommitment "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  --arg maxAddBalanceWei "9007199254740993" \
  --arg maxSpendWei "115792089237316195423570985008687907853269984665640564039457584007913129639935" \
  --arg composeHash "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
  --arg composeRoot "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" \
  --argjson composeCount 1 \
  --arg manager "0x1111111111111111111111111111111111111111" \
  --arg managerRoot "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
  --argjson managerCount 1 \
  --arg releaseCommitment "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
  --arg releaseMaxAddBalanceWei "9007199254740993" \
  --arg releaseMaxSpendWei "115792089237316195423570985008687907853269984665640564039457584007913129639935" \
  --arg releaseComposeRoot "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" \
  --argjson releaseComposeCount 1 \
  --arg releaseManagerRoot "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
  --argjson releaseManagerCount 1 \
  --arg pendingAccountCommitment "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg pendingMaxAddBalanceWei "0" \
  --arg pendingMaxSpendWei "0" \
  --arg pendingComposeRoot "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --argjson pendingComposeCount 0 \
  --arg pendingManagerRoot "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --argjson pendingManagerCount 0 \
  --arg pendingCommitment "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --argjson pendingActivatesAt 0 \
  --argjson releasePolicyFrozen true \
  --argjson emergencyHalted false \
  -f "$MANIFEST_FILTER" "$fixture_input" > "$fixture_output"

jq -e '
  .contracts.tinkerAccountEncumbrance.status == "deployed_exact_release_policy_frozen_active"
  and .contracts.tinkerAccountEncumbrance.sourceCommit == "deployment-source-commit"
  and .contracts.tinkerAccountEncumbrance.latestReleaseSourceCommit == "0123456789abcdef0123456789abcdef01234567"
  and .contracts.tinkerAccountEncumbrance.latestReleaseReviewEnvelopeSha256 == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  and .contracts.tinkerAccountEncumbrance.latestReleaseFinalAuthoritySha256 == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and (.contracts.tinkerAccountEncumbrance | has("latestReleaseOperatorPolicyPacketSha256") | not)
  and .contracts.tinkerAccountEncumbrance.pendingOwner == "0x0000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.maxAddBalanceWei == "9007199254740993"
  and (.contracts.tinkerAccountEncumbrance.maxAddBalanceWei | type) == "string"
  and .contracts.tinkerAccountEncumbrance.maxSpendWei == "115792089237316195423570985008687907853269984665640564039457584007913129639935"
  and (.contracts.tinkerAccountEncumbrance.maxSpendWei | type) == "string"
  and .contracts.tinkerAccountEncumbrance.approvedComposeHashes == ["0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]
  and .contracts.tinkerAccountEncumbrance.managers == ["0x1111111111111111111111111111111111111111"]
  and .contracts.tinkerAccountEncumbrance.releaseMaxAddBalanceWei == "9007199254740993"
  and .contracts.tinkerAccountEncumbrance.releaseComposeHashes == ["0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]
  and .contracts.tinkerAccountEncumbrance.releaseComposeRoot == .contracts.tinkerAccountEncumbrance.approvedComposeRoot
  and .contracts.tinkerAccountEncumbrance.releaseManagers == ["0x1111111111111111111111111111111111111111"]
  and .contracts.tinkerAccountEncumbrance.releaseManagerRoot == .contracts.tinkerAccountEncumbrance.managerRoot
  and .contracts.tinkerAccountEncumbrance.pendingMaxAddBalanceWei == "0"
  and .contracts.tinkerAccountEncumbrance.pendingMaxSpendWei == "0"
  and .contracts.tinkerAccountEncumbrance.pendingComposeHashes == []
  and .contracts.tinkerAccountEncumbrance.pendingManagers == []
  and .contracts.tinkerAccountEncumbrance.pendingReleasePolicyActivatesAt == 0
  and .contracts.tinkerAccountEncumbrance.perOperationCaps == true
  and .contracts.tinkerAccountEncumbrance.custodiesFunds == false
  and (.tinkerReleaseHistory | length) == 2
  and .tinkerReleaseHistory[0].encumbranceAddress == "0x2222222222222222222222222222222222222222"
  and .tinkerReleaseHistory[1].chainId == 84532
  and .tinkerReleaseHistory[1].encumbranceAddress == "0x1111111111111111111111111111111111111111"
  and .tinkerReleaseHistory[1].runtimeCodeHash == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and .tinkerReleaseHistory[0].finalAuthoritySha256 == .tinkerReleaseHistory[1].finalAuthoritySha256
  and .tinkerReleaseHistory[0].reviewEnvelopeSha256 != .tinkerReleaseHistory[1].reviewEnvelopeSha256
  and .tinkerReleaseHistory[1].reviewEnvelopeSha256 == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  and .tinkerReleaseHistory[1].finalAuthoritySha256 == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and (.tinkerReleaseHistory[1] | has("operatorPolicyPacketSha256") | not)
  and (.tinkerReleaseHistory[1].maxSpendWei | type) == "string"
' "$fixture_output" >/dev/null

echo "tinker exact release helper safety checks passed"
