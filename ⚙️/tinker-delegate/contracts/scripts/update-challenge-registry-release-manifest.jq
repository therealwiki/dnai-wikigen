def require($condition; $message):
  if $condition then . else error($message) end;

def zero_address: "0x0000000000000000000000000000000000000000";

def is_address:
  type == "string" and test("^0x[0-9a-fA-F]{40}$");

def is_nonzero_address:
  is_address and ascii_downcase != zero_address;

def is_bytes32:
  type == "string" and test("^0x[0-9a-fA-F]{64}$");

def is_nonzero_bytes32:
  is_bytes32 and ascii_downcase != ("0x" + ("0" * 64));

def is_sha256_digest:
  type == "string"
  and test("^sha256:[0-9a-f]{64}$")
  and . != ("sha256:" + ("0" * 64));

def is_source_commit:
  type == "string" and test("^[0-9a-f]{40}$") and . != ("0" * 40);

def is_safe_uint:
  type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;

def is_utc_timestamp:
  type == "string"
  and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$");

def exact_catalog_entry($index):
  keys == [
    "catalogKey",
    "catalogManifestHash",
    "challengeId",
    "configurationFrozen",
    "controller",
    "evaluatorCommitment",
    "lifecycle",
    "metadataHash",
    "metadataURI",
    "paused",
    "pendingController",
    "releasePolicyCommitment",
    "sealedArtifactCommitment",
    "version"
  ]
  and .challengeId == ($index + 1)
  and .version == 1
  and (.catalogKey | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}@(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"))
  and (.controller | is_nonzero_address)
  and (.pendingController | ascii_downcase) == zero_address
  and .lifecycle == "open"
  and (.paused | not)
  and .configurationFrozen
  and (.catalogManifestHash | is_nonzero_bytes32)
  and (.metadataURI | type == "string" and length > 0 and length <= 256)
  and (.metadataHash | is_nonzero_bytes32)
  and (.metadataHash | ascii_downcase) == (.catalogManifestHash | ascii_downcase)
  and (.sealedArtifactCommitment | is_nonzero_bytes32)
  and (.evaluatorCommitment | is_nonzero_bytes32)
  and (.releasePolicyCommitment | is_nonzero_bytes32)
  and ([
    (.metadataHash | ascii_downcase),
    (.sealedArtifactCommitment | ascii_downcase),
    (.evaluatorCommitment | ascii_downcase),
    (.releasePolicyCommitment | ascii_downcase)
  ] | unique | length) == 4;

def exact_projection:
  ($catalog | type) == "object"
  and ($catalog | keys) == [
    "chainId",
    "entries",
    "finalAuthoritySha256",
    "registry",
    "releaseSha",
    "schema"
  ]
  and $catalog.schema == "dnai.challenge-registry-authority-projection.v1"
  and $catalog.chainId == $chainId
  and $catalog.releaseSha == $sourceCommit
  and $catalog.finalAuthoritySha256 == $finalAuthoritySha256
  and ($catalog.registry | keys) == [
    "address",
    "expectedChallengeCount",
    "minimumVersionReviewDelaySeconds",
    "owner",
    "pendingOwner",
    "registryPaused",
    "runtimeCodeHash"
  ]
  and ($catalog.registry.address | ascii_downcase) == ($registryAddress | ascii_downcase)
  and ($catalog.registry.runtimeCodeHash | ascii_downcase) == ($runtimeCodeHash | ascii_downcase)
  and ($catalog.registry.owner | ascii_downcase) == ($operator | ascii_downcase)
  and ($catalog.registry.pendingOwner | ascii_downcase) == zero_address
  and ($catalog.registry.registryPaused | not)
  and $catalog.registry.minimumVersionReviewDelaySeconds == 172800
  and $catalog.registry.expectedChallengeCount == ($catalog.entries | length)
  and ($catalog.entries | type) == "array"
  and ($catalog.entries | length) >= 1
  and ($catalog.entries | length) <= 32
  and ([range(0; $catalog.entries | length) as $index
    | ($catalog.entries[$index] | exact_catalog_entry($index))] | all);

def exact_observed_entry($index):
  .catalogKey == $catalog.entries[$index].catalogKey
  and .challengeId == ($index + 1)
  and (.controller | ascii_downcase) == ($catalog.entries[$index].controller | ascii_downcase)
  and (.pendingController | ascii_downcase) == zero_address
  and .latestVersion == 1
  and (.paused | not)
  and (.controllerPaused | not)
  and (.governancePaused | not)
  and (.createdAt | is_safe_uint) and .createdAt > 0
  and (.updatedAt | is_safe_uint) and .updatedAt >= .createdAt
  and (.reviewEligibleAt | is_safe_uint)
  and .reviewEligibleAt == (.createdAt + 172800)
  and (.metadataURI == $catalog.entries[$index].metadataURI)
  and ((.metadataHash | ascii_downcase) == ($catalog.entries[$index].metadataHash | ascii_downcase))
  and ((.sealedArtifactCommitment | ascii_downcase) == ($catalog.entries[$index].sealedArtifactCommitment | ascii_downcase))
  and ((.evaluatorCommitment | ascii_downcase) == ($catalog.entries[$index].evaluatorCommitment | ascii_downcase))
  and ((.releasePolicyCommitment | ascii_downcase) == ($catalog.entries[$index].releasePolicyCommitment | ascii_downcase))
  and (
    if $phase == 1 then
      .lifecycle == "draft"
      and (.configurationFrozen | not)
      and .updatedAt == .createdAt
    else
      .lifecycle == "open"
      and .configurationFrozen
      and .updatedAt >= .reviewEligibleAt
    end
  );

def exact_transaction_receipt($index; $count):
  keys == [
    "blockHash",
    "blockNumber",
    "blockTimestamp",
    "calldataHash",
    "challengeId",
    "function",
    "transactionHash",
    "transactionIndex"
  ]
  and (.transactionHash | is_nonzero_bytes32)
  and (.calldataHash | is_nonzero_bytes32)
  and (.blockHash | is_nonzero_bytes32)
  and (.blockNumber | is_safe_uint) and .blockNumber > 0
  and (.blockTimestamp | is_safe_uint) and .blockTimestamp > 0
  and (.transactionIndex | is_safe_uint)
  and (
    if $phase == 1 then
      .challengeId == ($index + 1)
      and .function == "createChallenge"
    else
      .challengeId == (($index / 2 | floor) + 1)
      and (
        if ($index % 2) == 0 then .function == "freezeChallengeConfiguration"
        else .function == "setLifecycleOpen"
        end
      )
    end
  );

def transaction_occurs_before($left; $right):
  ($left.blockNumber < $right.blockNumber)
  or (
    $left.blockNumber == $right.blockNumber
    and $left.transactionIndex < $right.transactionIndex
  );

require(type == "object"; "deployment ledger must be a JSON object")
| require((.network | type) == "object" and .network.chainId == $chainId;
    "deployment ledger chainId mismatch")
| require((.contracts.challengeRegistry | type) == "object";
    "deployment ledger is missing contracts.challengeRegistry")
| require((.freshDeployment.contractSuite | type) == "object";
    "deployment ledger is missing freshDeployment.contractSuite")
| require(($chainId | is_safe_uint) and $chainId == 84532;
    "ChallengeRegistry release chainId must be Base Sepolia")
| require(($registryAddress | is_nonzero_address) and ($operator | is_nonzero_address);
    "ChallengeRegistry release addresses are invalid")
| require(($runtimeCodeHash | is_nonzero_bytes32);
    "ChallengeRegistry runtime code hash is invalid")
| require(($sourceCommit | is_source_commit);
    "ChallengeRegistry release source commit is invalid")
| require(($reviewEnvelopeSha256 | is_sha256_digest)
    and ($finalAuthoritySha256 | is_sha256_digest)
    and ($catalogProjectionSha256 | is_sha256_digest);
    "ChallengeRegistry release digest is invalid")
| require(($phase | is_safe_uint) and ($phase == 1 or $phase == 2);
    "ChallengeRegistry release phase is invalid")
| require(($recordedAt | is_utc_timestamp);
    "ChallengeRegistry release timestamp is invalid")
| require(($stateBlockNumber | is_safe_uint) and $stateBlockNumber > 0
    and ($stateBlockHash | is_nonzero_bytes32)
    and ($stateBlockTimestamp | is_safe_uint) and $stateBlockTimestamp > 0;
    "ChallengeRegistry pinned poststate block evidence is invalid")
| require(($latestCheckBlockNumber | is_safe_uint) and $latestCheckBlockNumber >= $stateBlockNumber
    and ($latestCheckBlockHash | is_nonzero_bytes32)
    and ($latestCheckBlockTimestamp | is_safe_uint) and $latestCheckBlockTimestamp >= $stateBlockTimestamp;
    "ChallengeRegistry latest-state recheck evidence is invalid")
| require(($status | type) == "string" and ($status | length) > 0 and ($status | length) <= 128;
    "ChallengeRegistry release status is invalid")
| require(($policyState | type) == "string" and ($policyState | length) > 0 and ($policyState | length) <= 160;
    "ChallengeRegistry release policy state is invalid")
| require((.contracts.challengeRegistry.address | ascii_downcase) == ($registryAddress | ascii_downcase);
    "deployment ledger ChallengeRegistry address mismatch")
| require((.contracts.challengeRegistry.runtimeCodeHash | ascii_downcase) == ($runtimeCodeHash | ascii_downcase);
    "deployment ledger ChallengeRegistry runtime code hash mismatch")
| require(.contracts.challengeRegistry.sourceCommit == $sourceCommit
    and .freshDeployment.contractSuite.sourceCommit == $sourceCommit;
    "deployment ledger ChallengeRegistry source commit mismatch")
| require(exact_projection;
    "ChallengeRegistry authority projection is invalid")
| require(($observedCatalog | type) == "array"
    and ($observedCatalog | length) == ($catalog.entries | length)
    and ([range(0; $observedCatalog | length) as $index
      | ($observedCatalog[$index] | exact_observed_entry($index))] | all);
    "observed ChallengeRegistry catalog does not match the exact phase state")
| (($catalog.entries | length) * (if $phase == 1 then 1 else 2 end)) as $expectedTransactions
| require(($transactionReceipts | type) == "array"
    and ($transactionReceipts | length) == $expectedTransactions
    and ([range(0; $expectedTransactions) as $index
      | ($transactionReceipts[$index] | exact_transaction_receipt($index; $catalog.entries | length))] | all)
    and ([$transactionReceipts[].transactionHash | ascii_downcase] | unique | length) == $expectedTransactions;
    "ChallengeRegistry transaction receipts are incomplete, duplicated, or out of order")
| require(([$transactionReceipts[].blockNumber] | max) <= $stateBlockNumber
    and ([$transactionReceipts[].blockTimestamp] | max) <= $stateBlockTimestamp
    and ([range(1; $expectedTransactions) as $index
      | transaction_occurs_before($transactionReceipts[$index - 1]; $transactionReceipts[$index])] | all)
    and (
      if $phase == 1 then
        ([range(0; $expectedTransactions) as $index
          | $transactionReceipts[$index].blockTimestamp == $observedCatalog[$index].createdAt] | all)
      else
        ([range(0; ($catalog.entries | length)) as $index
          | $transactionReceipts[$index * 2].blockTimestamp
              <= $transactionReceipts[($index * 2) + 1].blockTimestamp
            and $transactionReceipts[($index * 2) + 1].blockTimestamp
              == $observedCatalog[$index].updatedAt] | all)
      end
    );
    "ChallengeRegistry receipts are not ordered or bound to the pinned poststate")
| require((.challengeRegistryReleaseHistory // []) | type == "array";
    "challengeRegistryReleaseHistory must be an array")
| [(.challengeRegistryReleaseHistory // [])[]
    | select(((.challengeRegistryAddress // "") | ascii_downcase) == ($registryAddress | ascii_downcase))] as $registryHistory
| require(($registryHistory | length) == ($phase - 1)
    and ([$registryHistory[].phase] == [range(1; $phase)])
    and ([$registryHistory[]
      | .chainId == $chainId
        and ((.runtimeCodeHash // "") | ascii_downcase) == ($runtimeCodeHash | ascii_downcase)
        and .sourceCommit == $sourceCommit
        and (.reviewEnvelopeSha256 | is_sha256_digest)
        and .finalAuthoritySha256 == $finalAuthoritySha256
        and .catalogProjectionSha256 == $catalogProjectionSha256
        and .authorityCatalog == $catalog.entries] | all);
    "ChallengeRegistry release history is missing, duplicated, or out of order")
| require((.contracts.challengeRegistry.latestReleasePhase // 0) == ($phase - 1);
    "current ChallengeRegistry release phase is out of order")
| .contracts.challengeRegistry += {
    status: $status,
    policyState: $policyState,
    owner: $operator,
    pendingOwner: zero_address,
    registryPaused: false,
    challengeCount: ($catalog.entries | length),
    nextChallengeId: (($catalog.entries | length) + 1),
    minimumVersionReviewDelaySeconds: 172800,
    genesisCatalog: $observedCatalog,
    genesisCatalogProjectionSha256: $catalogProjectionSha256,
    latestReleasePhase: $phase,
    latestReleaseTransactions: $transactionReceipts,
    latestReleaseRecordedAt: $recordedAt,
    latestReleaseSourceCommit: $sourceCommit,
    latestReleaseReviewEnvelopeSha256: $reviewEnvelopeSha256,
    latestReleaseFinalAuthoritySha256: $finalAuthoritySha256,
    latestReleaseStateBlockNumber: $stateBlockNumber,
    latestReleaseStateBlockHash: $stateBlockHash,
    latestReleaseStateBlockTimestamp: $stateBlockTimestamp,
    latestReleaseLatestCheckBlockNumber: $latestCheckBlockNumber,
    latestReleaseLatestCheckBlockHash: $latestCheckBlockHash,
    latestReleaseLatestCheckBlockTimestamp: $latestCheckBlockTimestamp
  }
| .challengeRegistryReleaseHistory = ((.challengeRegistryReleaseHistory // []) + [{
    kind: "challenge_registry_exact_genesis_phase",
    chainId: $chainId,
    challengeRegistryAddress: $registryAddress,
    runtimeCodeHash: $runtimeCodeHash,
    sourceCommit: $sourceCommit,
    reviewEnvelopeSha256: $reviewEnvelopeSha256,
    finalAuthoritySha256: $finalAuthoritySha256,
    catalogProjectionSha256: $catalogProjectionSha256,
    phase: $phase,
    recordedAt: $recordedAt,
    status: $status,
    policyState: $policyState,
    authorityCatalog: $catalog.entries,
    transactionReceipts: $transactionReceipts,
    postState: {
      blockNumber: $stateBlockNumber,
      blockHash: $stateBlockHash,
      blockTimestamp: $stateBlockTimestamp,
      latestCheckBlockNumber: $latestCheckBlockNumber,
      latestCheckBlockHash: $latestCheckBlockHash,
      latestCheckBlockTimestamp: $latestCheckBlockTimestamp,
      owner: $operator,
      pendingOwner: zero_address,
      registryPaused: false,
      challengeCount: ($catalog.entries | length),
      nextChallengeId: (($catalog.entries | length) + 1),
      minimumVersionReviewDelaySeconds: 172800,
      challenges: $observedCatalog
    }
  }])
