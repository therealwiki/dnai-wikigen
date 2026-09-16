def require($condition; $message):
  if $condition then . else error($message) end;

def zero_address: "0x0000000000000000000000000000000000000000";
def zero_bytes32: "0x0000000000000000000000000000000000000000000000000000000000000000";

def is_address:
  type == "string" and test("^0x[0-9a-fA-F]{40}$");

def is_nonzero_address:
  is_address and ascii_downcase != zero_address;

def is_bytes32:
  type == "string" and test("^0x[0-9a-fA-F]{64}$");

def is_nonzero_bytes32:
  is_bytes32 and ascii_downcase != zero_bytes32;

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

def exact_phase_post_state:
  $globalSequence == 0
  and ($globalHead | ascii_downcase) == zero_bytes32
  and (
    if $phase == 1 then
      ($writer | ascii_downcase) == zero_address
      and ($writerReleaseCommitment | ascii_downcase) == zero_bytes32
      and ($pendingWriter | ascii_downcase) == ($releaseWriter | ascii_downcase)
      and ($pendingWriterReleaseCommitment | ascii_downcase) == ($releaseCommitment | ascii_downcase)
      and $pendingWriterActivatesAt > 0
      and ($writerRotationsFrozen | not)
      and $paused
    else
      ($writer | ascii_downcase) == ($releaseWriter | ascii_downcase)
      and ($writerReleaseCommitment | ascii_downcase) == ($releaseCommitment | ascii_downcase)
      and ($pendingWriter | ascii_downcase) == zero_address
      and ($pendingWriterReleaseCommitment | ascii_downcase) == zero_bytes32
      and $pendingWriterActivatesAt == 0
      and $writerRotationsFrozen
      and ($paused | not)
    end
  );

require(type == "object"; "deployment ledger must be a JSON object")
| require((.network | type) == "object" and .network.chainId == $chainId;
    "deployment ledger chainId mismatch")
| require((.contracts | type) == "object" and (.contracts.executionPolicyAnchor | type) == "object";
    "deployment ledger is missing contracts.executionPolicyAnchor")
| require((.freshDeployment.contractSuite | type) == "object";
    "deployment ledger is missing freshDeployment.contractSuite")
| require(($chainId | is_safe_uint) and $chainId == 84532;
    "release chainId must be Base Sepolia")
| require(($anchorAddress | is_nonzero_address);
    "ExecutionPolicyAnchor address is invalid")
| require(($runtimeCodeHash | is_nonzero_bytes32);
    "ExecutionPolicyAnchor runtime code hash is invalid")
| require(($sourceCommit | is_source_commit);
    "release source commit is invalid")
| require(($reviewEnvelopeSha256 | is_sha256_digest);
    "operator policy review-envelope hash is invalid")
| require(($finalAuthoritySha256 | is_sha256_digest);
    "operator policy final-authority hash is invalid")
| require(($phase | is_safe_uint) and ($phase == 1 or $phase == 2);
    "execution-policy anchor release phase is invalid")
| require(($transactionHash | is_nonzero_bytes32);
    "release transaction hash is invalid")
| require(($blockNumber | is_safe_uint) and $blockNumber > 0;
    "release block number is invalid")
| require(($blockTimestamp | is_safe_uint) and $blockTimestamp > 0;
    "release block timestamp is invalid")
| require(($recordedAt | is_utc_timestamp);
    "release timestamp is invalid")
| require(($status | type) == "string" and ($status | length) > 0 and ($status | length) <= 120;
    "release status is invalid")
| require(($policyState | type) == "string" and ($policyState | length) > 0 and ($policyState | length) <= 160;
    "release policy state is invalid")
| require(($releaseWriter | is_nonzero_address);
    "release writer is invalid")
| require(($releaseCommitment | is_nonzero_bytes32);
    "release commitment is invalid")
| require(($writer | is_address) and ($pendingWriter | is_address);
    "writer post-state address is invalid")
| require(($writerReleaseCommitment | is_bytes32)
    and ($pendingWriterReleaseCommitment | is_bytes32)
    and ($globalHead | is_bytes32);
    "writer post-state commitment is invalid")
| require(($pendingWriterActivatesAt | is_safe_uint)
    and ($globalSequence | is_safe_uint);
    "writer post-state integer is invalid")
| require(($writerRotationsFrozen | type) == "boolean" and ($paused | type) == "boolean";
    "writer post-state boolean is invalid")
| require((.contracts.executionPolicyAnchor.address | type) == "string"
    and (.contracts.executionPolicyAnchor.address | ascii_downcase) == ($anchorAddress | ascii_downcase);
    "deployment ledger ExecutionPolicyAnchor address mismatch")
| require((.contracts.executionPolicyAnchor.runtimeCodeHash | type) == "string"
    and (.contracts.executionPolicyAnchor.runtimeCodeHash | ascii_downcase) == ($runtimeCodeHash | ascii_downcase);
    "deployment ledger ExecutionPolicyAnchor runtime code hash mismatch")
| require(.contracts.executionPolicyAnchor.sourceCommit == $sourceCommit
    and .freshDeployment.contractSuite.sourceCommit == $sourceCommit;
    "deployment ledger release source commit mismatch")
| require((.executionPolicyAnchorReleaseHistory // []) | type == "array";
    "executionPolicyAnchorReleaseHistory must be an array")
| [(.executionPolicyAnchorReleaseHistory // [])[]
    | select(
        .chainId == $chainId
        and ((.executionPolicyAnchorAddress // "") | ascii_downcase) == ($anchorAddress | ascii_downcase)
        and ((.runtimeCodeHash // "") | ascii_downcase) == ($runtimeCodeHash | ascii_downcase)
        and .sourceCommit == $sourceCommit
        and .finalAuthoritySha256 == $finalAuthoritySha256
      )
    | .phase] as $recordedPhases
| require($recordedPhases == [range(1; $phase)];
    "execution-policy anchor release history is missing, duplicated, or out of order")
| require((.contracts.executionPolicyAnchor.latestReleasePhase // 0) == ($phase - 1);
    "current ExecutionPolicyAnchor release phase is out of order")
| require(exact_phase_post_state;
    "ExecutionPolicyAnchor post-state is inconsistent with the release phase")
| .contracts.executionPolicyAnchor += {
    status: $status,
    writer: $writer,
    writerReleaseCommitment: $writerReleaseCommitment,
    pendingWriter: $pendingWriter,
    pendingWriterReleaseCommitment: $pendingWriterReleaseCommitment,
    pendingWriterActivatesAt: $pendingWriterActivatesAt,
    writerRotationsFrozen: $writerRotationsFrozen,
    paused: $paused,
    globalSequence: $globalSequence,
    globalHead: $globalHead,
    policyState: $policyState,
    latestReleasePhase: $phase,
    latestReleaseTx: $transactionHash,
    latestReleaseBlock: $blockNumber,
    latestReleaseBlockTimestamp: $blockTimestamp,
    latestReleaseRecordedAt: $recordedAt,
    latestReleaseSourceCommit: $sourceCommit,
    latestReleaseReviewEnvelopeSha256: $reviewEnvelopeSha256,
    latestReleaseFinalAuthoritySha256: $finalAuthoritySha256
  }
| .executionPolicyAnchorReleaseHistory = ((.executionPolicyAnchorReleaseHistory // []) + [{
    kind: "execution_policy_anchor_exact_writer_release_phase",
    chainId: $chainId,
    executionPolicyAnchorAddress: $anchorAddress,
    runtimeCodeHash: $runtimeCodeHash,
    sourceCommit: $sourceCommit,
    reviewEnvelopeSha256: $reviewEnvelopeSha256,
    finalAuthoritySha256: $finalAuthoritySha256,
    phase: $phase,
    transactionHash: $transactionHash,
    blockNumber: $blockNumber,
    blockTimestamp: $blockTimestamp,
    recordedAt: $recordedAt,
    status: $status,
    policyState: $policyState,
    releaseWriter: $releaseWriter,
    releaseCommitment: $releaseCommitment,
    postState: {
      writer: $writer,
      writerReleaseCommitment: $writerReleaseCommitment,
      pendingWriter: $pendingWriter,
      pendingWriterReleaseCommitment: $pendingWriterReleaseCommitment,
      pendingWriterActivatesAt: $pendingWriterActivatesAt,
      writerRotationsFrozen: $writerRotationsFrozen,
      paused: $paused,
      globalSequence: $globalSequence,
      globalHead: $globalHead
    }
  }])
