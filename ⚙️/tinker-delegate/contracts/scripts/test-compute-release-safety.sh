#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/configure-compute-release.sh"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"
MANIFEST_FILTER="$SCRIPT_DIR/update-compute-release-manifest.jq"
USDC_VERIFIER="$SCRIPT_DIR/verify-base-sepolia-usdc-release.sh"

test -f "$TARGET"
test -f "$MANIFEST_FILTER"
test -f "$USDC_VERIFIER"
bash -n "$TARGET"
bash -n "$POLICY_GUARD"
bash -n "$USDC_VERIFIER"
grep -Fq '$developerFeeBps <= 100' "$MANIFEST_FILTER"
grep -Fq '. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"' "$TARGET"
test "$(grep -Ec '^[[:space:]]*operator_policy_project_and_validate$' "$TARGET")" -eq 1
policy_line="$(grep -n -m1 '^[[:space:]]*operator_policy_project_and_validate$' "$TARGET" | cut -d: -f1)"
wallet_line="$(grep -n -m1 'cast wallet list' "$TARGET" | cut -d: -f1)"
dry_run_line="$(grep -n -m1 '^forge script' "$TARGET" | cut -d: -f1)"
if [ "$policy_line" -ge "$wallet_line" ] || [ "$policy_line" -ge "$dry_run_line" ]; then
  echo "Compute operator policy must fail closed before wallet access or simulation." >&2
  exit 1
fi
grep -Fq 'operator_policy_assert_public_env contractEnv COMPUTE_VAULT_METERING_VERIFIER' "$TARGET"
grep -Fq 'operator_policy_assert_public_env contractEnv COMPUTE_VAULT_METERING_QVL_VERIFIER' "$TARGET"
grep -Fq 'operator_policy_assert_public_env contractEnv COMPUTE_VAULT_DEVELOPER' "$TARGET"
grep -Fq 'operator_policy_assert_public_env contractEnv COMPUTE_VAULT_DEVELOPER_FEE_BPS' "$TARGET"
for usdc_authority_env in \
  COMPUTE_VAULT_ERC20_ASSET_ADDRESS \
  COMPUTE_VAULT_ERC20_ASSET_CODE_HASH \
  COMPUTE_VAULT_ERC20_ASSET_SYMBOL \
  COMPUTE_VAULT_ERC20_ASSET_DECIMALS; do
  grep -Fq "operator_policy_assert_public_env postDeployEnv $usdc_authority_env" "$TARGET"
done
grep -Fq 'BASE_SEPOLIA_SECONDARY_RPC_URL' "$TARGET" "$USDC_VERIFIER"
grep -Fq 'eth_getBlockByNumber "$block_tag" false' "$USDC_VERIFIER"
grep -Fq 'eth_getCode "$asset" "$block_hex"' "$USDC_VERIFIER"
grep -Fq 'eth_call "$call_object" "$block_hex"' "$USDC_VERIFIER"
grep -Fq 'two_distinct_https_rpcs_exact_finalized_numeric_block_eth_getCode_and_eth_call_agreement' "$TARGET" "$USDC_VERIFIER"
if [ "$(grep -Ec '^[[:space:]]*verify_canonical_usdc_finalized_authority$' "$TARGET")" -ne 2 ]; then
  echo "Compute release must prove canonical USDC before wallet access and immediately before broadcast." >&2
  exit 1
fi
first_usdc_proof_line="$(grep -n -m1 '^[[:space:]]*verify_canonical_usdc_finalized_authority$' "$TARGET" | cut -d: -f1)"
last_usdc_proof_line="$(grep -n '^[[:space:]]*verify_canonical_usdc_finalized_authority$' "$TARGET" | tail -n1 | cut -d: -f1)"
forge_broadcast_line="$(grep -n '^forge script script/ConfigureComputeRelease.s.sol' "$TARGET" | tail -n1 | cut -d: -f1)"
if [ "$first_usdc_proof_line" -ge "$wallet_line" ] \
  || [ "$last_usdc_proof_line" -le "$wallet_line" ] \
  || [ "$last_usdc_proof_line" -ge "$forge_broadcast_line" ]; then
  echo "Canonical USDC proof ordering does not guard the Compute release broadcast boundary." >&2
  exit 1
fi
grep -Fq "developer()(address)" "$TARGET"
grep -Fq "developerFeeBps()(uint16)" "$TARGET"
for policy_env in \
  COMPUTE_VAULT_TEE_IDENTITY \
  COMPUTE_VAULT_COMPOSE_HASH \
  COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT \
  COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT \
  COMPUTE_VAULT_NATIVE_PROVIDER \
  COMPUTE_VAULT_ERC20_PROVIDER \
  COMPUTE_METERING_POLICY_SET_HASH; do
  grep -Fq "$policy_env" "$TARGET"
done
if grep -Eq '(^|[[:space:]])eval[[:space:]]|^[[:space:]]*(source|\.)[[:space:]]+.*OPERATOR_POLICY_PROJECTION' "$POLICY_GUARD" "$TARGET"; then
  echo "Compute release must never evaluate or source operator-policy projection JSON." >&2
  exit 1
fi
grep -Fq 'ACCOUNT=dev' "$TARGET"
grep -Fq -- '--account dev' "$TARGET"
grep -Fq 'status --porcelain --untracked-files=normal' "$TARGET"
grep -Fq 'RELEASE_SHA must equal the exact lowercase checked-out commit' "$TARGET"
if [ "$(grep -Ec '^[[:space:]]*check_release_provenance$' "$TARGET")" -lt 3 ]; then
  echo "Compute release must recheck source immediately before and after keystore unlock." >&2
  exit 1
fi
grep -Fq 'for frozen_getter in assetAdditionsFrozen ratePolicyAdditionsFrozen composePolicyFrozen teeIdentityAdditionsFrozen meteringBindingFrozen' "$TARGET"
grep -Fq 'allowedAssetCount()(uint256)' "$TARGET"
grep -Fq 'activeRatePolicyCount()(uint256)' "$TARGET"
grep -Fq 'approvedComposeCount()(uint256)' "$TARGET"
grep -Fq 'cast codehash "$COMPUTE_VAULT_ADDRESS"' "$TARGET"
grep -Fq 'COMPUTE_VAULT_RUNTIME_CODE_HASH' "$TARGET"
grep -Fq 'validate_bytes32 COMPUTE_VAULT_RUNTIME_CODE_HASH "$COMPUTE_VAULT_RUNTIME_CODE_HASH"' "$TARGET"
grep -Fq 'approvedTeeIdentityCount()(uint256)' "$TARGET"
grep -Fq 'pendingAssetCount()(uint256)' "$TARGET"
grep -Fq 'pendingRatePolicyCount()(uint256)' "$TARGET"
grep -Fq 'pendingComposeCount()(uint256)' "$TARGET"
grep -Fq 'pendingTeeIdentityCount()(uint256)' "$TARGET"
grep -Fq 'meteringPolicySetHash()(bytes32)' "$TARGET"
grep -Fq 'meteringQvlVerifier()(address)' "$TARGET"
grep -Fq 'pendingMeteringVerifier()(address)' "$TARGET"
grep -Fq 'pendingMeteringQvlVerifier()(address)' "$TARGET"
grep -Fq 'pendingMeteringPolicySetHash()(bytes32)' "$TARGET"
grep -Fq 'pendingMeteringBindingActivatesAt()(uint64)' "$TARGET"
grep -Fq 'meteringBindingFrozen()(bool)' "$TARGET"
grep -Fq 'COMPUTE_METERING_POLICY_SET_HASH' "$TARGET"
grep -Fq 'ComputeCreditVault must remain paused through phase 2.' "$TARGET"
grep -Fq "ratePolicies(bytes32)(address,address,uint16,bool)" "$TARGET"
grep -Fq 'COMPUTE_VAULT_NATIVE_PROVIDER' "$TARGET"
grep -Fq 'COMPUTE_VAULT_ERC20_PROVIDER' "$TARGET"
grep -Fq -- '--json' "$TARGET"
grep -Fq 'jq -er' "$TARGET"

for ceremony_digest in \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  reviewEnvelopeSha256 \
  finalAuthoritySha256; do
  if ! grep -Fq "$ceremony_digest" "$TARGET" "$MANIFEST_FILTER"; then
    echo "Compute release evidence is missing ceremony digest: $ceremony_digest" >&2
    exit 1
  fi
done
if grep -Eq 'operatorPolicy(Packet|Authority)Sha256|OPERATOR_POLICY_(PACKET|AUTHORITY)_SHA256' "$TARGET" "$MANIFEST_FILTER"; then
  echo "Compute ceremony evidence must use final-authority and review-envelope terminology." >&2
  exit 1
fi
if grep -Eq 'freshDeployment\.contractSuite\.(reviewEnvelopeSha256|finalAuthoritySha256)' "$TARGET" "$MANIFEST_FILTER"; then
  echo "Final authority or its renewable review envelope must not rewrite fresh-deployment history." >&2
  exit 1
fi

ledger_line="$(grep -n -m1 '^[[:space:]]*validate_existing_deployment_ledger$' "$TARGET" | cut -d: -f1)"
if [ "$ledger_line" -ge "$wallet_line" ] || [ "$ledger_line" -ge "$dry_run_line" ]; then
  echo "Broadcast ledger identity must fail closed before wallet access or simulation." >&2
  exit 1
fi
if [ "$(grep -Ec '^[[:space:]]*validate_existing_deployment_ledger$' "$TARGET")" -lt 4 ]; then
  echo "Compute release must revalidate its ledger before unlock, signing, and the atomic merge." >&2
  exit 1
fi
for ledger_boundary in \
  'computeReleaseHistory' \
  'latestUsdcFinalizedAuthority' \
  'usdcFinalizedAuthority' \
  'latestReleaseTransactions' \
  'transactionHash' \
  'blockNumber' \
  'blockTimestamp' \
  'cast receipt "$transaction_hash" status --confirmations 1' \
  'cast block "$confirmed_block_number" timestamp' \
  'status == "0x1"' \
  'unexpected broadcast transaction count' \
  'broadcast transaction targets a different contract' \
  'broadcast transaction function order mismatch' \
  'mktemp "${MANIFEST_PATH}.tmp.XXXXXX"' \
  'manifest_before_blob="$(deployment_ledger_blob)"' \
  'Deployment ledger changed concurrently' \
  'operator_policy_durably_replace_release_ledger "$tmp_manifest" "$MANIFEST_PATH"' \
  'cleanup_compute_manifest_temp'; do
  if ! grep -Fq "$ledger_boundary" "$TARGET" "$MANIFEST_FILTER"; then
    echo "Compute release ledger boundary is missing: $ledger_boundary" >&2
    exit 1
  fi
done

dry_exit_line="$(grep -n -m1 'Dry run complete; no chain state changed.' "$TARGET" | cut -d: -f1)"
temp_line="$(grep -n -m1 'tmp_manifest="$(mktemp' "$TARGET" | cut -d: -f1)"
if [ "$dry_exit_line" -ge "$temp_line" ]; then
  echo "Dry-run flow must exit before any deployment-ledger temporary file is created." >&2
  exit 1
fi

if grep -Eq -- '--private-key|PRIVATE_KEY|raw private' "$TARGET"; then
  echo "compute release helper contains a forbidden raw-key path" >&2
  exit 1
fi

# Exercise the read-only USDC verifier with a fake JSON-RPC transport. Local
# ABI decoding and Keccak hashing still use the installed reviewed cast binary;
# only network methods are intercepted. Every negative case must fail closed.
probe_fixture_dir="$(mktemp -d)"
probe_bin="$probe_fixture_dir/bin"
mkdir -p "$probe_bin"
real_cast="$(command -v cast)"
cat > "$probe_bin/cast" <<'FAKE_CAST'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "rpc" ]; then
  exec "$REAL_CAST" "$@"
fi
if [ "${2:-}" != "--rpc-url" ] || [ "$#" -lt 4 ]; then
  exit 97
fi
rpc_url="$3"
method="$4"
shift 4
case "$rpc_url" in
  https://primary.example/rpc) provider=primary ;;
  https://secondary.example/rpc) provider=secondary ;;
  *) exit 98 ;;
esac
scenario="${FAKE_RPC_SCENARIO:-success}"
hash_one=0x1111111111111111111111111111111111111111111111111111111111111111
hash_two=0x2222222222222222222222222222222222222222222222222222222222222222
decimals_six=0x0000000000000000000000000000000000000000000000000000000000000006
decimals_seven=0x0000000000000000000000000000000000000000000000000000000000000007
symbol_usdc=0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000045553444300000000000000000000000000000000000000000000000000000000
symbol_usdt=0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000045553445400000000000000000000000000000000000000000000000000000000
case "$method" in
  eth_chainId)
    if [ "$scenario" = chain_divergence ] && [ "$provider" = secondary ]; then
      printf '%s\n' '"0x1"'
    else
      printf '%s\n' '"0x14a34"'
    fi
    ;;
  eth_getBlockByNumber)
    block_tag="${1:-}"
    [ "${2:-}" = false ] || exit 96
    number=0x64
    hash="$hash_one"
    if [ "$block_tag" = finalized ]; then
      if [ "$scenario" = finalized_number_divergence ] && [ "$provider" = secondary ]; then
        number=0x65
      fi
      if [ "$scenario" = finalized_hash_divergence ] && [ "$provider" = secondary ]; then
        hash="$hash_two"
      fi
    elif [ "$block_tag" = 0x64 ]; then
      if [ "$scenario" = numeric_block_drift ] && [ "$provider" = secondary ]; then
        hash="$hash_two"
      fi
    else
      exit 95
    fi
    printf '{"number":"%s","hash":"%s"}\n' "$number" "$hash"
    ;;
  eth_getCode)
    [ "${1:-}" = 0x036cbd53842c5426634e7929541ec2318f3dcf7e ] || exit 94
    [ "${2:-}" = 0x64 ] || exit 93
    if [ "$scenario" = unsupported_numeric_state ] && [ "$provider" = secondary ]; then
      exit 92
    fi
    if [ "$scenario" = code_divergence ] && [ "$provider" = secondary ]; then
      printf '%s\n' '"0x6001"'
    else
      printf '%s\n' '"0x6000"'
    fi
    ;;
  eth_call)
    call_object="${1:-}"
    [ "${2:-}" = 0x64 ] || exit 91
    if [[ "$call_object" == *313ce567* ]]; then
      if [ "$scenario" = decimals_divergence ] && [ "$provider" = secondary ]; then
        printf '"%s"\n' "$decimals_seven"
      else
        printf '"%s"\n' "$decimals_six"
      fi
    elif [[ "$call_object" == *95d89b41* ]]; then
      if { [ "$scenario" = symbol_divergence ] && [ "$provider" = secondary ]; } \
        || [ "$scenario" = both_symbols_wrong ]; then
        printf '"%s"\n' "$symbol_usdt"
      else
        printf '"%s"\n' "$symbol_usdc"
      fi
    else
      exit 90
    fi
    ;;
  *) exit 89 ;;
esac
FAKE_CAST
chmod 0700 "$probe_bin/cast"

expected_probe_code_hash="$(cast keccak 0x6000 | tr '[:upper:]' '[:lower:]')"
run_usdc_probe() {
  local scenario="$1"
  local expected_code_hash="${2:-$expected_probe_code_hash}"
  PATH="$probe_bin:$PATH" \
  REAL_CAST="$real_cast" \
  FAKE_RPC_SCENARIO="$scenario" \
  BASE_SEPOLIA_RPC_URL=https://primary.example/rpc \
  BASE_SEPOLIA_SECONDARY_RPC_URL=https://secondary.example/rpc \
  COMPUTE_VAULT_ERC20_ASSET_ADDRESS=0x036cbd53842c5426634e7929541ec2318f3dcf7e \
  COMPUTE_VAULT_ERC20_ASSET_CODE_HASH="$expected_code_hash" \
  COMPUTE_VAULT_ERC20_ASSET_SYMBOL=USDC \
  COMPUTE_VAULT_ERC20_ASSET_DECIMALS=6 \
    bash "$USDC_VERIFIER"
}

happy_probe_receipt="$(run_usdc_probe success)"
jq -e \
  --arg codeHash "$expected_probe_code_hash" '
    .schema == "dnai.base-sepolia-usdc-finalized-authority.v1"
    and .chainId == 84532
    and .finalizedBlockNumber == 100
    and .finalizedBlockHash == ("0x" + ("1" * 64))
    and .assetAddress == "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
    and .runtimeCodeHash == $codeHash
    and .symbol == "USDC"
    and .decimals == 6
  ' <<<"$happy_probe_receipt" >/dev/null

for scenario in \
  chain_divergence \
  finalized_number_divergence \
  finalized_hash_divergence \
  unsupported_numeric_state \
  code_divergence \
  decimals_divergence \
  symbol_divergence \
  both_symbols_wrong \
  numeric_block_drift; do
  if run_usdc_probe "$scenario" >/dev/null 2>&1; then
    echo "Canonical USDC verifier accepted negative scenario: $scenario" >&2
    exit 1
  fi
done
if run_usdc_probe success 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  >/dev/null 2>&1; then
  echo "Canonical USDC verifier accepted runtime code outside signed final authority." >&2
  exit 1
fi
if PATH="$probe_bin:$PATH" REAL_CAST="$real_cast" FAKE_RPC_SCENARIO=success \
  BASE_SEPOLIA_RPC_URL=https://primary.example/rpc \
  BASE_SEPOLIA_SECONDARY_RPC_URL=https://primary.example/other \
  COMPUTE_VAULT_ERC20_ASSET_ADDRESS=0x036cbd53842c5426634e7929541ec2318f3dcf7e \
  COMPUTE_VAULT_ERC20_ASSET_CODE_HASH="$expected_probe_code_hash" \
  COMPUTE_VAULT_ERC20_ASSET_SYMBOL=USDC \
  COMPUTE_VAULT_ERC20_ASSET_DECIMALS=6 \
    bash "$USDC_VERIFIER" >/dev/null 2>&1; then
  echo "Canonical USDC verifier accepted two endpoints on the same RPC origin." >&2
  exit 1
fi
rm -rf -- "$probe_fixture_dir"

fixture_dir="$(mktemp -d)"
trap 'rm -rf -- "$fixture_dir"' EXIT
fixture_input="$fixture_dir/input.json"
phase_one_output="$fixture_dir/phase-one.json"
phase_two_output="$fixture_dir/phase-two.json"
phase_three_output="$fixture_dir/phase-three.json"
bad_input="$fixture_dir/bad-input.json"
bad_output="$fixture_dir/bad-output.json"

chain_id=84532
vault=0x1111111111111111111111111111111111111111
runtime=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=0123456789abcdef0123456789abcdef01234567
review_one=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
review_two=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
review_three=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
final_authority=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
tee=0x2222222222222222222222222222222222222222
compose=0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
native_policy=0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
erc20_policy=0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
native_provider=0x3333333333333333333333333333333333333333
erc20_provider=0x4444444444444444444444444444444444444444
metering_verifier=0x5555555555555555555555555555555555555555
metering_qvl_verifier=0x6666666666666666666666666666666666666666
metering_policy=0x1111111111111111111111111111111111111111111111111111111111111111
usdc=0x036cbd53842c5426634e7929541ec2318f3dcf7e
usdc_code_hash=0x7777777777777777777777777777777777777777777777777777777777777777
usdc_finalized_authority="$(jq -cn \
  --arg assetAddress "$usdc" \
  --arg runtimeCodeHash "$usdc_code_hash" '
  {
    schema: "dnai.base-sepolia-usdc-finalized-authority.v1",
    chainId: 84532,
    finalizedBlockNumber: 44487090,
    finalizedBlockHash: ("0x" + ("8" * 64)),
    assetAddress: $assetAddress,
    runtimeCodeHash: $runtimeCodeHash,
    symbol: "USDC",
    decimals: 6,
    proof: "two_distinct_https_rpcs_exact_finalized_numeric_block_eth_getCode_and_eth_call_agreement"
  }')"
zero_address=0x0000000000000000000000000000000000000000
zero_bytes32=0x0000000000000000000000000000000000000000000000000000000000000000
phase_one_transactions="$(jq -cn '[range(1; 5) as $i | {
  transactionHash: ("0x" + ("a" * 63) + ($i | tostring)),
  blockNumber: (1000 + $i),
  blockTimestamp: (2000000000 + $i)
}]')"
phase_two_transactions="$(jq -cn '[range(1; 8) as $i | {
  transactionHash: ("0x" + ("b" * 63) + ($i | tostring)),
  blockNumber: (2000 + $i),
  blockTimestamp: (2000000100 + $i)
}]')"
phase_three_transactions="$(jq -cn '[range(1; 8) as $i | {
  transactionHash: ("0x" + ("c" * 63) + ($i | tostring)),
  blockNumber: (3000 + $i),
  blockTimestamp: (2000000200 + $i)
}]')"

jq -n \
  --arg vault "$vault" \
  --arg runtime "$runtime" \
  --arg source "$source_commit" \
  '{
    schemaVersion: 2,
    network: {name: "Base Sepolia", chainId: 84532},
    untouchedTopLevel: {sentinel: "preserve-me"},
    contracts: {
      computeCreditVault: {
        address: $vault,
        runtimeCodeHash: $runtime,
        sourceCommit: $source,
        deploymentTx: "preserve-deployment-transaction",
        verificationStatus: "preserve-verification",
        unrelatedNested: {sentinel: 42}
      },
      unrelatedContract: {sentinel: "preserve-contract"}
    },
    freshDeployment: {contractSuite: {
      sourceCommit: $source,
      deploymentIntentSha256: "preserve-deployment-intent",
      operatorPolicyPacketSha256: "historical-deploy-only-value"
    }},
    computeReleaseHistory: [],
    unrelatedHistory: [{sentinel: "preserve-history"}]
  }' > "$fixture_input"

merge_phase() {
  local input="$1"
  local output="$2"
  local phase="$3"
  local review_envelope="$4"
  local final_authority_digest="$5"
  local transactions="$6"
  local developer_fee_bps=100
  local developer_fee_frozen=true
  local active_metering_verifier pending_metering_verifier active_metering_qvl_verifier pending_metering_qvl_verifier
  local active_metering_policy pending_metering_policy
  local pending_metering_at metering_frozen paused
  local allowed_count rate_count compose_count tee_count pending_asset_count pending_rate_count pending_compose_count pending_tee_count
  local asset_frozen rate_frozen compose_frozen tee_frozen usdc_allowed pending_asset_at compose_approved pending_compose_at
  local active_tee_compose pending_tee_compose pending_tee_at
  local native_active_asset native_active_provider native_active_fee native_active
  local native_pending_asset native_pending_provider native_pending_fee native_pending_at
  local erc20_active_asset erc20_active_provider erc20_active_fee erc20_active
  local erc20_pending_asset erc20_pending_provider erc20_pending_fee erc20_pending_at

  if [ "$phase" = "1" ]; then
    active_metering_verifier="$zero_address"
    active_metering_qvl_verifier="$zero_address"
    active_metering_policy="$zero_bytes32"
    pending_metering_verifier="$metering_verifier"
    pending_metering_qvl_verifier="$metering_qvl_verifier"
    pending_metering_policy="$metering_policy"
    pending_metering_at=1100
    metering_frozen=false
    paused=true
    allowed_count=0
    rate_count=0
    compose_count=0
    tee_count=0
    pending_asset_count=1
    pending_rate_count=1
    pending_compose_count=1
    pending_tee_count=0
    asset_frozen=false
    rate_frozen=false
    compose_frozen=false
    tee_frozen=false
    usdc_allowed=false
    pending_asset_at=1101
    compose_approved=false
    pending_compose_at=1102
    active_tee_compose="$zero_bytes32"
    pending_tee_compose="$zero_bytes32"
    pending_tee_at=0
    native_active_asset="$zero_address"
    native_active_provider="$zero_address"
    native_active_fee=0
    native_active=false
    native_pending_asset="$zero_address"
    native_pending_provider="$native_provider"
    native_pending_fee=100
    native_pending_at=1103
    erc20_active_asset="$zero_address"
    erc20_active_provider="$zero_address"
    erc20_active_fee=0
    erc20_active=false
    erc20_pending_asset="$zero_address"
    erc20_pending_provider="$zero_address"
    erc20_pending_fee=0
    erc20_pending_at=0
  elif [ "$phase" = "2" ]; then
    active_metering_verifier="$metering_verifier"
    active_metering_qvl_verifier="$metering_qvl_verifier"
    active_metering_policy="$metering_policy"
    pending_metering_verifier="$zero_address"
    pending_metering_qvl_verifier="$zero_address"
    pending_metering_policy="$zero_bytes32"
    pending_metering_at=0
    metering_frozen=true
    paused=true
    allowed_count=1
    rate_count=1
    compose_count=1
    tee_count=0
    pending_asset_count=0
    pending_rate_count=1
    pending_compose_count=0
    pending_tee_count=1
    asset_frozen=false
    rate_frozen=false
    compose_frozen=false
    tee_frozen=false
    usdc_allowed=true
    pending_asset_at=0
    compose_approved=true
    pending_compose_at=0
    active_tee_compose="$zero_bytes32"
    pending_tee_compose="$compose"
    pending_tee_at=2100
    native_active_asset="$zero_address"
    native_active_provider="$native_provider"
    native_active_fee=100
    native_active=true
    native_pending_asset="$zero_address"
    native_pending_provider="$zero_address"
    native_pending_fee=0
    native_pending_at=0
    erc20_active_asset="$zero_address"
    erc20_active_provider="$zero_address"
    erc20_active_fee=0
    erc20_active=false
    erc20_pending_asset="$usdc"
    erc20_pending_provider="$erc20_provider"
    erc20_pending_fee=100
    erc20_pending_at=2200
  else
    active_metering_verifier="$metering_verifier"
    active_metering_qvl_verifier="$metering_qvl_verifier"
    active_metering_policy="$metering_policy"
    pending_metering_verifier="$zero_address"
    pending_metering_qvl_verifier="$zero_address"
    pending_metering_policy="$zero_bytes32"
    pending_metering_at=0
    metering_frozen=true
    paused=false
    allowed_count=1
    rate_count=2
    compose_count=1
    tee_count=1
    pending_asset_count=0
    pending_rate_count=0
    pending_compose_count=0
    pending_tee_count=0
    asset_frozen=true
    rate_frozen=true
    compose_frozen=true
    tee_frozen=true
    usdc_allowed=true
    pending_asset_at=0
    compose_approved=true
    pending_compose_at=0
    active_tee_compose="$compose"
    pending_tee_compose="$zero_bytes32"
    pending_tee_at=0
    native_active_asset="$zero_address"
    native_active_provider="$native_provider"
    native_active_fee=100
    native_active=true
    native_pending_asset="$zero_address"
    native_pending_provider="$zero_address"
    native_pending_fee=0
    native_pending_at=0
    erc20_active_asset="$usdc"
    erc20_active_provider="$erc20_provider"
    erc20_active_fee=100
    erc20_active=true
    erc20_pending_asset="$zero_address"
    erc20_pending_provider="$zero_address"
    erc20_pending_fee=0
    erc20_pending_at=0
  fi

  jq -e \
    --argjson chainId "$chain_id" \
    --arg vaultAddress "$vault" \
    --arg runtimeCodeHash "$runtime" \
    --arg sourceCommit "$source_commit" \
    --arg reviewEnvelopeSha256 "$review_envelope" \
    --arg finalAuthoritySha256 "$final_authority_digest" \
    --argjson phase "$phase" \
    --argjson transactions "$transactions" \
    --arg recordedAt "2026-07-21T12:00:00Z" \
    --arg teeIdentity "$tee" \
    --arg composeHash "$compose" \
    --arg nativePolicyCommitment "$native_policy" \
    --arg erc20PolicyCommitment "$erc20_policy" \
    --arg nativeProvider "$native_provider" \
    --arg erc20Provider "$erc20_provider" \
    --arg meteringVerifierExpected "$metering_verifier" \
    --arg meteringQvlVerifierExpected "$metering_qvl_verifier" \
    --arg meteringPolicySetHashExpected "$metering_policy" \
    --arg baseSepoliaUsdc "$usdc" \
    --arg baseSepoliaUsdcCodeHash "$usdc_code_hash" \
    --arg baseSepoliaUsdcSymbol "USDC" \
    --argjson baseSepoliaUsdcDecimals 6 \
    --argjson usdcFinalizedAuthority "$usdc_finalized_authority" \
    --argjson developerFeeBps "$developer_fee_bps" \
    --argjson developerFeeFrozen "$developer_fee_frozen" \
    --arg meteringVerifier "$active_metering_verifier" \
    --arg meteringQvlVerifier "$active_metering_qvl_verifier" \
    --arg meteringPolicySetHash "$active_metering_policy" \
    --arg pendingMeteringVerifier "$pending_metering_verifier" \
    --arg pendingMeteringQvlVerifier "$pending_metering_qvl_verifier" \
    --arg pendingMeteringPolicySetHash "$pending_metering_policy" \
    --argjson pendingMeteringActivatesAt "$pending_metering_at" \
    --argjson meteringBindingFrozen "$metering_frozen" \
    --argjson paused "$paused" \
    --argjson allowedAssetCount "$allowed_count" \
    --argjson activeRatePolicyCount "$rate_count" \
    --argjson approvedComposeCount "$compose_count" \
    --argjson approvedTeeCount "$tee_count" \
    --argjson pendingAssetCount "$pending_asset_count" \
    --argjson pendingRatePolicyCount "$pending_rate_count" \
    --argjson pendingComposeCount "$pending_compose_count" \
    --argjson pendingTeeCount "$pending_tee_count" \
    --argjson assetAdditionsFrozen "$asset_frozen" \
    --argjson ratePolicyAdditionsFrozen "$rate_frozen" \
    --argjson composePolicyFrozen "$compose_frozen" \
    --argjson teeIdentityAdditionsFrozen "$tee_frozen" \
    --argjson usdcAllowed "$usdc_allowed" \
    --argjson pendingAssetActivatesAt "$pending_asset_at" \
    --argjson composeApproved "$compose_approved" \
    --argjson pendingComposeActivatesAt "$pending_compose_at" \
    --arg activeTeeComposeHash "$active_tee_compose" \
    --arg pendingTeeComposeHash "$pending_tee_compose" \
    --argjson pendingTeeActivatesAt "$pending_tee_at" \
    --arg nativeActiveAsset "$native_active_asset" \
    --arg nativeActiveProvider "$native_active_provider" \
    --argjson nativeActiveFeeBps "$native_active_fee" \
    --argjson nativeActive "$native_active" \
    --arg nativePendingAsset "$native_pending_asset" \
    --arg nativePendingProvider "$native_pending_provider" \
    --argjson nativePendingFeeBps "$native_pending_fee" \
    --argjson nativePendingActivatesAt "$native_pending_at" \
    --arg erc20ActiveAsset "$erc20_active_asset" \
    --arg erc20ActiveProvider "$erc20_active_provider" \
    --argjson erc20ActiveFeeBps "$erc20_active_fee" \
    --argjson erc20Active "$erc20_active" \
    --arg erc20PendingAsset "$erc20_pending_asset" \
    --arg erc20PendingProvider "$erc20_pending_provider" \
    --argjson erc20PendingFeeBps "$erc20_pending_fee" \
    --argjson erc20PendingActivatesAt "$erc20_pending_at" \
    -f "$MANIFEST_FILTER" "$input" > "$output"
}

merge_phase "$fixture_input" "$phase_one_output" 1 "$review_one" "$final_authority" "$phase_one_transactions"
jq -e \
  --arg review "$review_one" \
  --arg final "$final_authority" \
  --argjson usdcFinalizedAuthority "$usdc_finalized_authority" \
  '
    .untouchedTopLevel.sentinel == "preserve-me"
    and .contracts.unrelatedContract.sentinel == "preserve-contract"
    and .contracts.computeCreditVault.deploymentTx == "preserve-deployment-transaction"
    and .contracts.computeCreditVault.verificationStatus == "preserve-verification"
    and .contracts.computeCreditVault.unrelatedNested.sentinel == 42
    and .freshDeployment.contractSuite.deploymentIntentSha256 == "preserve-deployment-intent"
    and .freshDeployment.contractSuite.operatorPolicyPacketSha256 == "historical-deploy-only-value"
    and .unrelatedHistory == [{sentinel: "preserve-history"}]
    and .contracts.computeCreditVault.latestReleasePhase == 1
    and .contracts.computeCreditVault.latestReleaseReviewEnvelopeSha256 == $review
    and .contracts.computeCreditVault.latestReleaseFinalAuthoritySha256 == $final
    and .contracts.computeCreditVault.latestUsdcFinalizedAuthority == $usdcFinalizedAuthority
    and .contracts.computeCreditVault.pendingAssetCount == 1
    and .contracts.computeCreditVault.pendingRatePolicyCount == 1
    and .contracts.computeCreditVault.pendingComposeCount == 1
    and .contracts.computeCreditVault.meteringQvlVerifier == "0x0000000000000000000000000000000000000000"
    and .contracts.computeCreditVault.pendingMeteringQvlVerifier == "0x6666666666666666666666666666666666666666"
    and .contracts.computeCreditVault.paused == true
    and .computeReleaseHistory == [
      .computeReleaseHistory[0]
      | select(
          .kind == "compute_exact_release_policy_phase"
          and .phase == 1
          and .reviewEnvelopeSha256 == $review
          and .finalAuthoritySha256 == $final
          and .usdcFinalizedAuthority == $usdcFinalizedAuthority
          and (.transactions | length) == 4
          and (.transactionHashes | length) == 4
          and (.blockNumbers | length) == 4
          and (.blockTimestamps | length) == 4
        )
    ]
  ' "$phase_one_output" >/dev/null

# A renewable phase-two review envelope is allowed while the stable final
# authority, contract identity, source, and ordered history remain unchanged.
merge_phase "$phase_one_output" "$phase_two_output" 2 "$review_two" "$final_authority" "$phase_two_transactions"
jq -e \
  --arg reviewOne "$review_one" \
  --arg reviewTwo "$review_two" \
  --arg final "$final_authority" \
  --argjson usdcFinalizedAuthority "$usdc_finalized_authority" \
  '
    .contracts.computeCreditVault.latestReleasePhase == 2
    and .contracts.computeCreditVault.latestReleaseReviewEnvelopeSha256 == $reviewTwo
    and .contracts.computeCreditVault.latestReleaseFinalAuthoritySha256 == $final
    and (.computeReleaseHistory | length) == 2
    and .computeReleaseHistory[0].reviewEnvelopeSha256 == $reviewOne
    and .computeReleaseHistory[1].reviewEnvelopeSha256 == $reviewTwo
    and all(.computeReleaseHistory[]; .finalAuthoritySha256 == $final)
    and all(.computeReleaseHistory[]; .usdcFinalizedAuthority == $usdcFinalizedAuthority)
    and .untouchedTopLevel.sentinel == "preserve-me"
    and .contracts.computeCreditVault.deploymentTx == "preserve-deployment-transaction"
  ' "$phase_two_output" >/dev/null

merge_phase "$phase_two_output" "$phase_three_output" 3 "$review_three" "$final_authority" "$phase_three_transactions"
jq -e \
  --arg reviewThree "$review_three" \
  --arg final "$final_authority" \
  --arg tee "$tee" \
  --arg compose "$compose" \
  --argjson usdcFinalizedAuthority "$usdc_finalized_authority" \
  '
    .contracts.computeCreditVault.status == "deployed_exact_compute_release_policy_frozen_active"
    and .contracts.computeCreditVault.policyState == "exact_timelocked_compute_release_policy_frozen_active"
    and .contracts.computeCreditVault.latestReleasePhase == 3
    and .contracts.computeCreditVault.latestReleaseReviewEnvelopeSha256 == $reviewThree
    and .contracts.computeCreditVault.latestReleaseFinalAuthoritySha256 == $final
    and .contracts.computeCreditVault.paused == false
    and .contracts.computeCreditVault.assetAdditionsFrozen == true
    and .contracts.computeCreditVault.ratePolicyAdditionsFrozen == true
    and .contracts.computeCreditVault.composePolicyFrozen == true
    and .contracts.computeCreditVault.teeIdentityAdditionsFrozen == true
    and .contracts.computeCreditVault.meteringBindingFrozen == true
    and .contracts.computeCreditVault.meteringVerifier == "0x5555555555555555555555555555555555555555"
    and .contracts.computeCreditVault.meteringQvlVerifier == "0x6666666666666666666666666666666666666666"
    and .contracts.computeCreditVault.pendingMeteringVerifier == "0x0000000000000000000000000000000000000000"
    and .contracts.computeCreditVault.pendingMeteringQvlVerifier == "0x0000000000000000000000000000000000000000"
    and .contracts.computeCreditVault.activeRatePolicyCount == 2
    and (.contracts.computeCreditVault.activeRatePolicies | length) == 2
    and .contracts.computeCreditVault.approvedTeeIdentities == [$tee]
    and .contracts.computeCreditVault.teeIdentityComposeBindings == [{teeIdentity: $tee, composeHash: $compose}]
    and (.computeReleaseHistory | map(.phase)) == [1, 2, 3]
    and all(.computeReleaseHistory[]; .finalAuthoritySha256 == $final)
    and all(.computeReleaseHistory[]; .usdcFinalizedAuthority == $usdcFinalizedAuthority)
    and .untouchedTopLevel.sentinel == "preserve-me"
    and .freshDeployment.contractSuite.deploymentIntentSha256 == "preserve-deployment-intent"
  ' "$phase_three_output" >/dev/null

valid_usdc_finalized_authority="$usdc_finalized_authority"
usdc_finalized_authority="$(jq -c \
  '.runtimeCodeHash = "0x9999999999999999999999999999999999999999999999999999999999999999"' \
  <<<"$valid_usdc_finalized_authority")"
if merge_phase "$fixture_input" "$bad_output" 1 "$review_one" "$final_authority" \
  "$phase_one_transactions" >/dev/null 2>&1; then
  echo "Compute ledger merge accepted USDC proof outside the signed runtime authority." >&2
  exit 1
fi
usdc_finalized_authority="$valid_usdc_finalized_authority"

jq --arg bad "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  '.contracts.computeCreditVault.runtimeCodeHash = $bad' "$fixture_input" > "$bad_input"
if merge_phase "$bad_input" "$bad_output" 1 "$review_one" "$final_authority" "$phase_one_transactions" >/dev/null 2>&1; then
  echo "Compute ledger merge accepted a mismatched runtime code hash." >&2
  exit 1
fi

jq '.contracts.computeCreditVault.address = "0x9999999999999999999999999999999999999999"' \
  "$fixture_input" > "$bad_input"
if merge_phase "$bad_input" "$bad_output" 1 "$review_one" "$final_authority" "$phase_one_transactions" >/dev/null 2>&1; then
  echo "Compute ledger merge accepted a different vault address." >&2
  exit 1
fi

jq '.contracts.computeCreditVault.sourceCommit = "fedcba9876543210fedcba9876543210fedcba98"' \
  "$fixture_input" > "$bad_input"
if merge_phase "$bad_input" "$bad_output" 1 "$review_one" "$final_authority" "$phase_one_transactions" >/dev/null 2>&1; then
  echo "Compute ledger merge accepted a mismatched deployment source." >&2
  exit 1
fi

if merge_phase "$phase_one_output" "$bad_output" 1 "$review_one" "$final_authority" "$phase_one_transactions" >/dev/null 2>&1; then
  echo "Compute ledger merge accepted a duplicated or out-of-order phase." >&2
  exit 1
fi

wrong_authority=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
if merge_phase "$phase_one_output" "$bad_output" 2 "$review_two" "$wrong_authority" "$phase_two_transactions" >/dev/null 2>&1; then
  echo "Compute ledger merge allowed final-authority drift between phases." >&2
  exit 1
fi

duplicate_transactions="$(printf '%s' "$phase_one_transactions" | jq '.[1].transactionHash = .[0].transactionHash')"
if merge_phase "$fixture_input" "$bad_output" 1 "$review_one" "$final_authority" "$duplicate_transactions" >/dev/null 2>&1; then
  echo "Compute ledger merge accepted duplicate transaction evidence." >&2
  exit 1
fi

echo "compute release helper safety checks passed"
