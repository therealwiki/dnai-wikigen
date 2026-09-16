def require($condition; $message):
  if $condition then . else error($message) end;

def is_address:
  type == "string" and test("^0x[0-9a-fA-F]{40}$");

def is_bytes32:
  type == "string" and test("^0x[0-9a-fA-F]{64}$");

def is_nonzero_bytes32:
  is_bytes32 and (ascii_downcase != ("0x" + ("0" * 64)));

def is_source_commit:
  type == "string" and test("^[0-9a-f]{40}$") and . != ("0" * 40);

def is_sha256_digest:
  type == "string"
  and test("^sha256:[0-9a-f]{64}$")
  and . != ("sha256:" + ("0" * 64));

def is_safe_uint:
  type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;

def is_utc_timestamp:
  type == "string"
  and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$");

def zero_address: "0x0000000000000000000000000000000000000000";
def zero_bytes32: "0x0000000000000000000000000000000000000000000000000000000000000000";

def expected_transaction_count($releasePhase):
  if $releasePhase == 1 then 4 else 7 end;

def release_status($releasePhase):
  if $releasePhase == 1 then "deployed_paused_phase_1_pending_initial_timelocks"
  elif $releasePhase == 2 then "deployed_paused_phase_2_pending_final_timelocks"
  else "deployed_exact_compute_release_policy_frozen_active"
  end;

def release_policy_state($releasePhase):
  if $releasePhase == 1 then "execution_fail_closed_phase_1_pending_initial_timelocks"
  elif $releasePhase == 2 then "execution_fail_closed_phase_2_pending_final_timelocks"
  else "exact_timelocked_compute_release_policy_frozen_active"
  end;

def valid_transactions($expectedCount):
  type == "array"
  and length == $expectedCount
  and all(.[].transactionHash;
    type == "string"
    and test("^0x[0-9a-f]{64}$")
    and . != ("0x" + ("0" * 64)))
  and all(.[].blockNumber; is_safe_uint and . > 0)
  and all(.[].blockTimestamp; is_safe_uint and . > 0)
  and ([.[].transactionHash] | unique | length) == length;

def valid_usdc_finalized_authority($asset; $runtimeCodeHash; $symbol; $decimals):
  type == "object"
  and keys == [
    "assetAddress",
    "chainId",
    "decimals",
    "finalizedBlockHash",
    "finalizedBlockNumber",
    "proof",
    "runtimeCodeHash",
    "schema",
    "symbol"
  ]
  and .schema == "dnai.base-sepolia-usdc-finalized-authority.v1"
  and .chainId == 84532
  and ((.assetAddress | ascii_downcase) == ($asset | ascii_downcase))
  and ((.runtimeCodeHash | ascii_downcase) == ($runtimeCodeHash | ascii_downcase))
  and .symbol == $symbol
  and .decimals == $decimals
  and (.finalizedBlockNumber | is_safe_uint and . > 0)
  and (.finalizedBlockHash | is_nonzero_bytes32)
  and .proof == "two_distinct_https_rpcs_exact_finalized_numeric_block_eth_getCode_and_eth_call_agreement";

. as $root
| require(type == "object"; "deployment ledger must be a JSON object")
| require((.network | type) == "object" and .network.chainId == $chainId;
    "deployment ledger chainId mismatch")
| require((.contracts | type) == "object" and (.contracts.computeCreditVault | type) == "object";
    "deployment ledger is missing contracts.computeCreditVault")
| require((.freshDeployment.contractSuite | type) == "object";
    "deployment ledger is missing freshDeployment.contractSuite")
| require(($chainId | is_safe_uint) and $chainId == 84532;
    "release chainId must be Base Sepolia")
| require(($vaultAddress | is_address) and ($vaultAddress | ascii_downcase) != zero_address;
    "ComputeCreditVault address is invalid")
| require(($runtimeCodeHash | is_nonzero_bytes32);
    "ComputeCreditVault runtime code hash is invalid")
| require(($sourceCommit | is_source_commit);
    "release source commit is invalid")
| require(($reviewEnvelopeSha256 | is_sha256_digest);
    "operator policy review-envelope hash is invalid")
| require(($finalAuthoritySha256 | is_sha256_digest);
    "operator policy final-authority hash is invalid")
| require(($phase | is_safe_uint) and ($phase == 1 or $phase == 2 or $phase == 3);
    "compute release phase is invalid")
| require(($transactions | valid_transactions(expected_transaction_count($phase)));
    "compute release transaction evidence is invalid")
| require(($recordedAt | is_utc_timestamp); "release timestamp is invalid")
| require(($teeIdentity | is_address) and ($teeIdentity | ascii_downcase) != zero_address;
    "compute TEE identity is invalid")
| require(($composeHash | is_nonzero_bytes32);
    "compute compose hash is invalid")
| require(($nativePolicyCommitment | is_nonzero_bytes32)
    and ($erc20PolicyCommitment | is_nonzero_bytes32)
    and (($nativePolicyCommitment | ascii_downcase) != ($erc20PolicyCommitment | ascii_downcase));
    "compute rate policy commitments are invalid")
| require(($nativeProvider | is_address) and ($nativeProvider | ascii_downcase) != zero_address
    and ($erc20Provider | is_address) and ($erc20Provider | ascii_downcase) != zero_address;
    "compute providers are invalid")
| require(($meteringVerifierExpected | is_address)
    and ($meteringVerifierExpected | ascii_downcase) != zero_address
    and ($meteringQvlVerifierExpected | is_address)
    and ($meteringQvlVerifierExpected | ascii_downcase) != zero_address
    and (($meteringVerifierExpected | ascii_downcase) != ($meteringQvlVerifierExpected | ascii_downcase))
    and ($meteringPolicySetHashExpected | is_nonzero_bytes32);
    "compute metering release binding is invalid")
| require(($baseSepoliaUsdc | is_address) and ($baseSepoliaUsdc | ascii_downcase) != zero_address;
    "Base Sepolia USDC address is invalid")
| require(($baseSepoliaUsdcCodeHash | is_nonzero_bytes32)
    and $baseSepoliaUsdcSymbol == "USDC"
    and ($baseSepoliaUsdcDecimals | is_safe_uint) and $baseSepoliaUsdcDecimals == 6;
    "Base Sepolia USDC signed authority is invalid")
| require(($usdcFinalizedAuthority
      | valid_usdc_finalized_authority(
          $baseSepoliaUsdc;
          $baseSepoliaUsdcCodeHash;
          $baseSepoliaUsdcSymbol;
          $baseSepoliaUsdcDecimals));
    "Base Sepolia USDC finalized authority receipt is invalid")
| require(($meteringVerifier | is_address) and ($meteringQvlVerifier | is_address)
    and ($pendingMeteringVerifier | is_address) and ($pendingMeteringQvlVerifier | is_address)
    and ($meteringPolicySetHash | is_bytes32) and ($pendingMeteringPolicySetHash | is_bytes32)
    and ($activeTeeComposeHash | is_bytes32) and ($pendingTeeComposeHash | is_bytes32);
    "compute address or bytes32 post-state is invalid")
| require(($nativeActiveAsset | is_address) and ($nativeActiveProvider | is_address)
    and ($nativePendingAsset | is_address) and ($nativePendingProvider | is_address)
    and ($erc20ActiveAsset | is_address) and ($erc20ActiveProvider | is_address)
    and ($erc20PendingAsset | is_address) and ($erc20PendingProvider | is_address);
    "compute rate-policy address post-state is invalid")
| require(($developerFeeBps | is_safe_uint)
    and ($allowedAssetCount | is_safe_uint)
    and ($activeRatePolicyCount | is_safe_uint)
    and ($approvedComposeCount | is_safe_uint)
    and ($approvedTeeCount | is_safe_uint)
    and ($pendingAssetCount | is_safe_uint)
    and ($pendingRatePolicyCount | is_safe_uint)
    and ($pendingComposeCount | is_safe_uint)
    and ($pendingTeeCount | is_safe_uint)
    and ($pendingAssetActivatesAt | is_safe_uint)
    and ($pendingComposeActivatesAt | is_safe_uint)
    and ($pendingTeeActivatesAt | is_safe_uint)
    and ($pendingMeteringActivatesAt | is_safe_uint)
    and ($nativeActiveFeeBps | is_safe_uint)
    and ($nativePendingFeeBps | is_safe_uint)
    and ($nativePendingActivatesAt | is_safe_uint)
    and ($erc20ActiveFeeBps | is_safe_uint)
    and ($erc20PendingFeeBps | is_safe_uint)
    and ($erc20PendingActivatesAt | is_safe_uint);
    "numeric compute post-state is invalid")
| require(($developerFeeFrozen | type) == "boolean"
    and ($paused | type) == "boolean"
    and ($meteringBindingFrozen | type) == "boolean"
    and ($assetAdditionsFrozen | type) == "boolean"
    and ($ratePolicyAdditionsFrozen | type) == "boolean"
    and ($composePolicyFrozen | type) == "boolean"
    and ($teeIdentityAdditionsFrozen | type) == "boolean"
    and ($usdcAllowed | type) == "boolean"
    and ($composeApproved | type) == "boolean"
    and ($nativeActive | type) == "boolean"
    and ($erc20Active | type) == "boolean";
    "boolean compute post-state is invalid")
| require((.contracts.computeCreditVault.address | type) == "string"
    and (.contracts.computeCreditVault.address | ascii_downcase) == ($vaultAddress | ascii_downcase);
    "deployment ledger ComputeCreditVault address mismatch")
| require((.contracts.computeCreditVault.runtimeCodeHash | type) == "string"
    and (.contracts.computeCreditVault.runtimeCodeHash | ascii_downcase) == ($runtimeCodeHash | ascii_downcase);
    "deployment ledger ComputeCreditVault runtime code hash mismatch")
| require(.contracts.computeCreditVault.sourceCommit == $sourceCommit
    and .freshDeployment.contractSuite.sourceCommit == $sourceCommit;
    "deployment ledger release source commit mismatch")
| require((.computeReleaseHistory // []) | type == "array";
    "computeReleaseHistory must be an array")
| [(.computeReleaseHistory // [])[]
    | select(
        .chainId == $chainId
        and ((.computeCreditVaultAddress // "") | ascii_downcase) == ($vaultAddress | ascii_downcase)
        and ((.runtimeCodeHash // "") | ascii_downcase) == ($runtimeCodeHash | ascii_downcase)
        and .sourceCommit == $sourceCommit
        and .finalAuthoritySha256 == $finalAuthoritySha256
      )
    | .phase] as $recordedPhases
| require($recordedPhases == [range(1; $phase)];
    "compute release history is missing, duplicated, or out of order")
| require((.contracts.computeCreditVault.latestReleasePhase // 0) == ($phase - 1);
    "current ComputeCreditVault release phase is out of order")
| require($developerFeeFrozen and $developerFeeBps <= 100;
    "compute developer fee is not exact and frozen")
| require(
    if $phase == 1 then
      $allowedAssetCount == 0 and $activeRatePolicyCount == 0
      and $approvedComposeCount == 0 and $approvedTeeCount == 0
      and $pendingAssetCount == 1 and $pendingRatePolicyCount == 1
      and $pendingComposeCount == 1 and $pendingTeeCount == 0
      and $pendingAssetActivatesAt > 0 and $pendingComposeActivatesAt > 0
      and $pendingTeeActivatesAt == 0
      and ($usdcAllowed | not) and ($composeApproved | not)
      and $activeTeeComposeHash == zero_bytes32 and $pendingTeeComposeHash == zero_bytes32
      and $meteringVerifier == zero_address and $meteringQvlVerifier == zero_address
      and $meteringPolicySetHash == zero_bytes32
      and ($pendingMeteringVerifier | ascii_downcase) == ($meteringVerifierExpected | ascii_downcase)
      and ($pendingMeteringQvlVerifier | ascii_downcase) == ($meteringQvlVerifierExpected | ascii_downcase)
      and ($pendingMeteringPolicySetHash | ascii_downcase) == ($meteringPolicySetHashExpected | ascii_downcase)
      and $pendingMeteringActivatesAt > 0 and ($meteringBindingFrozen | not)
      and ($nativeActive | not) and $nativeActiveAsset == zero_address
      and $nativeActiveProvider == zero_address and $nativeActiveFeeBps == 0
      and ($nativePendingAsset | ascii_downcase) == zero_address
      and ($nativePendingProvider | ascii_downcase) == ($nativeProvider | ascii_downcase)
      and $nativePendingFeeBps == $developerFeeBps and $nativePendingActivatesAt > 0
      and ($erc20Active | not) and $erc20ActiveAsset == zero_address
      and $erc20ActiveProvider == zero_address and $erc20ActiveFeeBps == 0
      and $erc20PendingAsset == zero_address and $erc20PendingProvider == zero_address
      and $erc20PendingFeeBps == 0 and $erc20PendingActivatesAt == 0
      and ($assetAdditionsFrozen | not) and ($ratePolicyAdditionsFrozen | not)
      and ($composePolicyFrozen | not) and ($teeIdentityAdditionsFrozen | not)
      and $paused
    elif $phase == 2 then
      $allowedAssetCount == 1 and $activeRatePolicyCount == 1
      and $approvedComposeCount == 1 and $approvedTeeCount == 0
      and $pendingAssetCount == 0 and $pendingRatePolicyCount == 1
      and $pendingComposeCount == 0 and $pendingTeeCount == 1
      and $pendingAssetActivatesAt == 0 and $pendingComposeActivatesAt == 0
      and $pendingTeeActivatesAt > 0
      and $usdcAllowed and $composeApproved
      and $activeTeeComposeHash == zero_bytes32
      and ($pendingTeeComposeHash | ascii_downcase) == ($composeHash | ascii_downcase)
      and ($meteringVerifier | ascii_downcase) == ($meteringVerifierExpected | ascii_downcase)
      and ($meteringQvlVerifier | ascii_downcase) == ($meteringQvlVerifierExpected | ascii_downcase)
      and ($meteringPolicySetHash | ascii_downcase) == ($meteringPolicySetHashExpected | ascii_downcase)
      and $pendingMeteringVerifier == zero_address
      and $pendingMeteringQvlVerifier == zero_address
      and $pendingMeteringPolicySetHash == zero_bytes32
      and $pendingMeteringActivatesAt == 0 and $meteringBindingFrozen
      and $nativeActive
      and ($nativeActiveAsset | ascii_downcase) == zero_address
      and ($nativeActiveProvider | ascii_downcase) == ($nativeProvider | ascii_downcase)
      and $nativeActiveFeeBps == $developerFeeBps
      and $nativePendingAsset == zero_address and $nativePendingProvider == zero_address
      and $nativePendingFeeBps == 0 and $nativePendingActivatesAt == 0
      and ($erc20Active | not) and $erc20ActiveAsset == zero_address
      and $erc20ActiveProvider == zero_address and $erc20ActiveFeeBps == 0
      and ($erc20PendingAsset | ascii_downcase) == ($baseSepoliaUsdc | ascii_downcase)
      and ($erc20PendingProvider | ascii_downcase) == ($erc20Provider | ascii_downcase)
      and $erc20PendingFeeBps == $developerFeeBps and $erc20PendingActivatesAt > 0
      and ($assetAdditionsFrozen | not) and ($ratePolicyAdditionsFrozen | not)
      and ($composePolicyFrozen | not) and ($teeIdentityAdditionsFrozen | not)
      and $paused
    else
      $allowedAssetCount == 1 and $activeRatePolicyCount == 2
      and $approvedComposeCount == 1 and $approvedTeeCount == 1
      and $pendingAssetCount == 0 and $pendingRatePolicyCount == 0
      and $pendingComposeCount == 0 and $pendingTeeCount == 0
      and $pendingAssetActivatesAt == 0 and $pendingComposeActivatesAt == 0
      and $pendingTeeActivatesAt == 0
      and $usdcAllowed and $composeApproved
      and ($activeTeeComposeHash | ascii_downcase) == ($composeHash | ascii_downcase)
      and $pendingTeeComposeHash == zero_bytes32
      and ($meteringVerifier | ascii_downcase) == ($meteringVerifierExpected | ascii_downcase)
      and ($meteringQvlVerifier | ascii_downcase) == ($meteringQvlVerifierExpected | ascii_downcase)
      and ($meteringPolicySetHash | ascii_downcase) == ($meteringPolicySetHashExpected | ascii_downcase)
      and $pendingMeteringVerifier == zero_address
      and $pendingMeteringQvlVerifier == zero_address
      and $pendingMeteringPolicySetHash == zero_bytes32
      and $pendingMeteringActivatesAt == 0 and $meteringBindingFrozen
      and $nativeActive
      and ($nativeActiveAsset | ascii_downcase) == zero_address
      and ($nativeActiveProvider | ascii_downcase) == ($nativeProvider | ascii_downcase)
      and $nativeActiveFeeBps == $developerFeeBps
      and $nativePendingAsset == zero_address and $nativePendingProvider == zero_address
      and $nativePendingFeeBps == 0 and $nativePendingActivatesAt == 0
      and $erc20Active
      and ($erc20ActiveAsset | ascii_downcase) == ($baseSepoliaUsdc | ascii_downcase)
      and ($erc20ActiveProvider | ascii_downcase) == ($erc20Provider | ascii_downcase)
      and $erc20ActiveFeeBps == $developerFeeBps
      and $erc20PendingAsset == zero_address and $erc20PendingProvider == zero_address
      and $erc20PendingFeeBps == 0 and $erc20PendingActivatesAt == 0
      and $assetAdditionsFrozen and $ratePolicyAdditionsFrozen
      and $composePolicyFrozen and $teeIdentityAdditionsFrozen
      and ($paused | not)
    end;
    "compute release post-state is inconsistent with the phase")
| {
    status: release_status($phase),
    policyState: release_policy_state($phase),
    developerFeeBps: $developerFeeBps,
    developerFeeFrozen: $developerFeeFrozen,
    meteringVerifier: $meteringVerifier,
    meteringQvlVerifier: $meteringQvlVerifier,
    meteringPolicySetHash: $meteringPolicySetHash,
    pendingMeteringVerifier: $pendingMeteringVerifier,
    pendingMeteringQvlVerifier: $pendingMeteringQvlVerifier,
    pendingMeteringPolicySetHash: $pendingMeteringPolicySetHash,
    pendingMeteringBindingActivatesAt: $pendingMeteringActivatesAt,
    meteringBindingFrozen: $meteringBindingFrozen,
    paused: $paused,
    allowedAssetCount: $allowedAssetCount,
    activeRatePolicyCount: $activeRatePolicyCount,
    approvedComposeCount: $approvedComposeCount,
    approvedTeeIdentityCount: $approvedTeeCount,
    pendingAssetCount: $pendingAssetCount,
    pendingRatePolicyCount: $pendingRatePolicyCount,
    pendingComposeCount: $pendingComposeCount,
    pendingTeeIdentityCount: $pendingTeeCount,
    assetAdditionsFrozen: $assetAdditionsFrozen,
    ratePolicyAdditionsFrozen: $ratePolicyAdditionsFrozen,
    composePolicyFrozen: $composePolicyFrozen,
    teeIdentityAdditionsFrozen: $teeIdentityAdditionsFrozen,
    enabledErc20Assets: (if $allowedAssetCount == 0 then [] else [$baseSepoliaUsdc] end),
    activeRatePolicies: (
      (if $nativeActive then [{
        commitment: $nativePolicyCommitment,
        asset: zero_address,
        provider: $nativeActiveProvider,
        developerFeeBps: $nativeActiveFeeBps
      }] else [] end)
      + (if $erc20Active then [{
        commitment: $erc20PolicyCommitment,
        asset: $baseSepoliaUsdc,
        provider: $erc20ActiveProvider,
        developerFeeBps: $erc20ActiveFeeBps
      }] else [] end)
    ),
    approvedComposeHashes: (if $approvedComposeCount == 0 then [] else [$composeHash] end),
    approvedTeeIdentities: (if $approvedTeeCount == 0 then [] else [$teeIdentity] end),
    teeIdentityComposeBindings: (
      if $approvedTeeCount == 0 then []
      else [{teeIdentity: $teeIdentity, composeHash: $activeTeeComposeHash}]
      end
    ),
    pendingAssetProposals: (
      if $pendingAssetCount == 0 then []
      else [{asset: $baseSepoliaUsdc, activatesAt: $pendingAssetActivatesAt}]
      end
    ),
    pendingRatePolicyProposals: (
      if $nativePendingActivatesAt > 0 then [{
        commitment: $nativePolicyCommitment,
        asset: zero_address,
        provider: $nativePendingProvider,
        developerFeeBps: $nativePendingFeeBps,
        activatesAt: $nativePendingActivatesAt
      }]
      elif $erc20PendingActivatesAt > 0 then [{
        commitment: $erc20PolicyCommitment,
        asset: $baseSepoliaUsdc,
        provider: $erc20PendingProvider,
        developerFeeBps: $erc20PendingFeeBps,
        activatesAt: $erc20PendingActivatesAt
      }]
      else []
      end
    ),
    pendingComposeProposals: (
      if $pendingComposeCount == 0 then []
      else [{composeHash: $composeHash, activatesAt: $pendingComposeActivatesAt}]
      end
    ),
    pendingTeeIdentityProposals: (
      if $pendingTeeCount == 0 then []
      else [{
        teeIdentity: $teeIdentity,
        composeHash: $pendingTeeComposeHash,
        activatesAt: $pendingTeeActivatesAt
      }]
      end
    )
  } as $postState
| .contracts.computeCreditVault += ($postState + {
    latestReleasePhase: $phase,
    latestReleaseTransactions: $transactions,
    latestReleaseTx: $transactions[-1].transactionHash,
    latestReleaseBlock: $transactions[-1].blockNumber,
    latestReleaseRecordedAt: $recordedAt,
    latestReleaseSourceCommit: $sourceCommit,
    latestReleaseReviewEnvelopeSha256: $reviewEnvelopeSha256,
    latestReleaseFinalAuthoritySha256: $finalAuthoritySha256,
    latestUsdcFinalizedAuthority: $usdcFinalizedAuthority
  })
| .computeReleaseHistory = ((.computeReleaseHistory // []) + [{
    kind: "compute_exact_release_policy_phase",
    chainId: $chainId,
    computeCreditVaultAddress: $vaultAddress,
    runtimeCodeHash: $runtimeCodeHash,
    sourceCommit: $sourceCommit,
    reviewEnvelopeSha256: $reviewEnvelopeSha256,
    finalAuthoritySha256: $finalAuthoritySha256,
    phase: $phase,
    transactions: $transactions,
    transactionHashes: [$transactions[].transactionHash],
    blockNumbers: [$transactions[].blockNumber],
    blockTimestamps: [$transactions[].blockTimestamp],
    recordedAt: $recordedAt,
    status: release_status($phase),
    policyState: release_policy_state($phase),
    teeIdentity: $teeIdentity,
    composeHash: $composeHash,
    nativeRatePolicyCommitment: $nativePolicyCommitment,
    erc20RatePolicyCommitment: $erc20PolicyCommitment,
    meteringVerifier: $meteringVerifierExpected,
    meteringQvlVerifier: $meteringQvlVerifierExpected,
    meteringPolicySetHash: $meteringPolicySetHashExpected,
    usdcFinalizedAuthority: $usdcFinalizedAuthority,
    postState: $postState
  }])
