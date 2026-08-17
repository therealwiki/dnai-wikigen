// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ExecutionPolicyAnchor - monotonic public witness for policy decisions
/// @notice Anchors only opaque, deterministic decision and resource commitments.
///         Policy inputs, artifacts, prompts, and evaluator output must remain
///         outside the chain. A release-bound writer advances one global hash
///         chain and one compare-and-set head per resource. This contract does
///         not decide policy and an event is not TDX attestation evidence.
/// @dev Fresh deployments start paused and without a writer. The owner must
///      timelock the exact writer/release pair before any append is possible.
contract ExecutionPolicyAnchor {
    uint256 public constant WRITER_ROTATION_DELAY = 2 days;

    bytes32 public constant ANCHOR_TYPEHASH = keccak256(
        "ExecutionPolicyAnchor(uint256 chainId,address anchor,uint256 sequence,bytes32 previousGlobalHead,bytes32 resourceHash,bytes32 previousResourceHead,bytes32 decisionHash,address writer,bytes32 writerReleaseCommitment)"
    );

    address public owner;
    address public pendingOwner;

    /// @notice Immutable SHA-256 commitment to the exact canonical deployment
    ///         intent that authorized this fresh seven-contract suite.
    bytes32 public immutable deploymentIntentSha256;
    /// @notice Immutable SHA-256 commitment to the exact artifact in which
    ///         every listed reviewer signed acceptance of the reviewer genesis.
    bytes32 public immutable reviewerAuthorityGenesisAcceptanceSha256;

    address public writer;
    bytes32 public writerReleaseCommitment;
    address public pendingWriter;
    bytes32 public pendingWriterReleaseCommitment;
    uint64 public pendingWriterActivatesAt;
    bool public writerRotationsFrozen;
    bool public paused = true;

    uint256 public globalSequence;
    bytes32 public globalHead;

    mapping(bytes32 resourceHash => bytes32 decisionHash) public resourceDecisionHead;
    mapping(bytes32 resourceHash => uint256 sequence) public resourceSequence;
    mapping(bytes32 decisionHash => uint256 sequence) public decisionSequence;

    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ReviewerAuthorityGenesisAcceptanceAnchored(
        bytes32 indexed deploymentIntentSha256, bytes32 indexed reviewerAuthorityGenesisAcceptanceSha256
    );
    event WriterProposed(address indexed writer, bytes32 indexed releaseCommitment, uint256 activatesAt);
    event WriterProposalCancelled(address indexed writer, bytes32 indexed releaseCommitment);
    event WriterActivated(address indexed previousWriter, address indexed newWriter, bytes32 indexed releaseCommitment);
    event WriterRotationsFrozen(address indexed writer, bytes32 indexed releaseCommitment);
    event PauseSet(bool paused, address indexed caller);
    event DecisionAnchored(
        uint256 indexed sequence,
        bytes32 indexed resourceHash,
        bytes32 indexed decisionHash,
        bytes32 previousGlobalHead,
        bytes32 newGlobalHead,
        bytes32 previousResourceHead,
        address writer,
        bytes32 writerReleaseCommitment
    );

    error NotOwner();
    error NotPendingOwner();
    error NotWriter();
    error ZeroAddress();
    error ZeroCommitment();
    error RoleConflict();
    error Paused();
    error NoStateChange();
    error ProposalExists();
    error ProposalMissing();
    error TimelockNotElapsed(uint256 activatesAt);
    error WriterRotationsAreFrozen();
    error WriterRotationsNotFrozen();
    error PendingWriterProposal();
    error WriterNotConfigured();
    error UnexpectedWriterReleaseCommitment(bytes32 expected, bytes32 supplied);
    error UnexpectedGlobalSequence(uint256 expected, uint256 supplied);
    error UnexpectedGlobalHead(bytes32 expected, bytes32 supplied);
    error UnexpectedResourceHead(bytes32 resourceHash, bytes32 expected, bytes32 supplied);
    error DecisionAlreadyAnchored(bytes32 decisionHash);
    error SequenceOverflow();
    error TimestampOverflow();

    constructor(
        address initialOwner,
        bytes32 initialDeploymentIntentSha256,
        bytes32 initialReviewerAuthorityGenesisAcceptanceSha256
    ) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (
            initialDeploymentIntentSha256 == bytes32(0) || initialReviewerAuthorityGenesisAcceptanceSha256 == bytes32(0)
        ) {
            revert ZeroCommitment();
        }
        owner = initialOwner;
        deploymentIntentSha256 = initialDeploymentIntentSha256;
        reviewerAuthorityGenesisAcceptanceSha256 = initialReviewerAuthorityGenesisAcceptanceSha256;
        emit OwnershipTransferred(address(0), initialOwner);
        emit ReviewerAuthorityGenesisAcceptanceAnchored(
            initialDeploymentIntentSha256, initialReviewerAuthorityGenesisAcceptanceSha256
        );
        emit PauseSet(true, initialOwner);
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function _checkOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    /// @notice Begin a two-step governance ownership transfer.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == owner) revert NoStateChange();
        if (newOwner == writer || newOwner == pendingWriter) revert RoleConflict();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Accept governance ownership. The writer can never become owner.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        if (msg.sender == writer || msg.sender == pendingWriter) revert RoleConflict();
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Stage the exact writer and immutable release commitment.
    /// @dev The same address may be proposed for a new release commitment while
    ///      rotations remain open, but the writer/commitment pair must change.
    function proposeWriter(address newWriter, bytes32 newReleaseCommitment) external onlyOwner {
        if (writerRotationsFrozen) revert WriterRotationsAreFrozen();
        if (pendingWriterActivatesAt != 0) revert ProposalExists();
        if (newWriter == address(0)) revert ZeroAddress();
        if (newReleaseCommitment == bytes32(0)) revert ZeroCommitment();
        if (newWriter == owner || newWriter == pendingOwner || newWriter == address(this)) revert RoleConflict();
        if (newWriter == writer && newReleaseCommitment == writerReleaseCommitment) revert NoStateChange();

        uint256 activatesAt = block.timestamp + WRITER_ROTATION_DELAY;
        if (activatesAt > type(uint64).max) revert TimestampOverflow();
        pendingWriter = newWriter;
        pendingWriterReleaseCommitment = newReleaseCommitment;
        // The explicit upper-bound check above makes this narrowing exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        pendingWriterActivatesAt = uint64(activatesAt);
        emit WriterProposed(newWriter, newReleaseCommitment, activatesAt);
    }

    /// @notice Activate the staged writer only after the immutable delay.
    function activateWriter() external onlyOwner {
        if (writerRotationsFrozen) revert WriterRotationsAreFrozen();
        uint64 activatesAt = pendingWriterActivatesAt;
        if (activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < activatesAt) revert TimelockNotElapsed(activatesAt);

        address newWriter = pendingWriter;
        if (newWriter == owner || newWriter == pendingOwner || newWriter == address(this)) revert RoleConflict();
        address previousWriter = writer;
        bytes32 newReleaseCommitment = pendingWriterReleaseCommitment;
        writer = newWriter;
        writerReleaseCommitment = newReleaseCommitment;
        _clearWriterProposal();
        emit WriterActivated(previousWriter, newWriter, newReleaseCommitment);
    }

    /// @notice Cancel a staged writer change. Available while paused.
    function cancelWriterProposal() external onlyOwner {
        if (pendingWriterActivatesAt == 0) revert ProposalMissing();
        address proposedWriter = pendingWriter;
        bytes32 proposedReleaseCommitment = pendingWriterReleaseCommitment;
        _clearWriterProposal();
        emit WriterProposalCancelled(proposedWriter, proposedReleaseCommitment);
    }

    /// @notice Permanently close writer admission for this anchor release.
    /// @dev Emergency pausing remains available. Writer recovery after this
    ///      freeze requires a new anchor contract and explicit release migration.
    function freezeWriterRotations() external onlyOwner {
        if (writerRotationsFrozen) revert WriterRotationsAreFrozen();
        if (writer == address(0) || writerReleaseCommitment == bytes32(0)) revert WriterNotConfigured();
        if (pendingWriterActivatesAt != 0) revert PendingWriterProposal();
        writerRotationsFrozen = true;
        emit WriterRotationsFrozen(writer, writerReleaseCommitment);
    }

    /// @notice Emergency-stop anchoring. The owner or active writer may pause;
    ///         only governance may resume.
    function setPaused(bool newPaused) external {
        if (newPaused) {
            if (msg.sender != owner && msg.sender != writer) revert NotWriter();
        } else {
            if (msg.sender != owner) revert NotOwner();
            if (writer == address(0) || writerReleaseCommitment == bytes32(0)) revert WriterNotConfigured();
            if (pendingWriterActivatesAt != 0) revert PendingWriterProposal();
            if (!writerRotationsFrozen) revert WriterRotationsNotFrozen();
        }
        if (paused == newPaused) revert NoStateChange();
        paused = newPaused;
        emit PauseSet(newPaused, msg.sender);
    }

    /// @notice Advance the global and resource-specific chains exactly once.
    /// @param expectedGlobalSequence Caller-observed global sequence.
    /// @param expectedGlobalHead Caller-observed global hash-chain head.
    /// @param resourceHash Opaque domain-separated resource commitment.
    /// @param expectedResourceHead Caller-observed decision head for resource.
    /// @param decisionHash Opaque deterministic execution-policy decision hash.
    /// @param expectedWriterReleaseCommitment Exact release bound to the caller.
    function anchorDecision(
        uint256 expectedGlobalSequence,
        bytes32 expectedGlobalHead,
        bytes32 resourceHash,
        bytes32 expectedResourceHead,
        bytes32 decisionHash,
        bytes32 expectedWriterReleaseCommitment
    ) external returns (uint256 newSequence, bytes32 newGlobalHead) {
        if (paused) revert Paused();
        if (msg.sender != writer) revert NotWriter();
        if (resourceHash == bytes32(0) || decisionHash == bytes32(0)) revert ZeroCommitment();
        if (expectedWriterReleaseCommitment != writerReleaseCommitment) {
            revert UnexpectedWriterReleaseCommitment(writerReleaseCommitment, expectedWriterReleaseCommitment);
        }
        if (expectedGlobalSequence != globalSequence) {
            revert UnexpectedGlobalSequence(globalSequence, expectedGlobalSequence);
        }
        if (expectedGlobalHead != globalHead) revert UnexpectedGlobalHead(globalHead, expectedGlobalHead);

        bytes32 currentResourceHead = resourceDecisionHead[resourceHash];
        if (expectedResourceHead != currentResourceHead) {
            revert UnexpectedResourceHead(resourceHash, currentResourceHead, expectedResourceHead);
        }
        if (decisionSequence[decisionHash] != 0) revert DecisionAlreadyAnchored(decisionHash);
        if (globalSequence == type(uint256).max) revert SequenceOverflow();

        newSequence = globalSequence + 1;
        newGlobalHead = computeAnchorHead(
            newSequence,
            expectedGlobalHead,
            resourceHash,
            expectedResourceHead,
            decisionHash,
            msg.sender,
            expectedWriterReleaseCommitment
        );

        globalSequence = newSequence;
        globalHead = newGlobalHead;
        resourceDecisionHead[resourceHash] = decisionHash;
        resourceSequence[resourceHash] = newSequence;
        decisionSequence[decisionHash] = newSequence;

        emit DecisionAnchored(
            newSequence,
            resourceHash,
            decisionHash,
            expectedGlobalHead,
            newGlobalHead,
            expectedResourceHead,
            msg.sender,
            expectedWriterReleaseCommitment
        );
    }

    /// @notice Deterministically reproduce a global anchor head off-chain.
    function computeAnchorHead(
        uint256 sequence,
        bytes32 previousGlobalHead,
        bytes32 resourceHash,
        bytes32 previousResourceHead,
        bytes32 decisionHash,
        address anchorWriter,
        bytes32 releaseCommitment
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                ANCHOR_TYPEHASH,
                block.chainid,
                address(this),
                sequence,
                previousGlobalHead,
                resourceHash,
                previousResourceHead,
                decisionHash,
                anchorWriter,
                releaseCommitment
            )
        );
    }

    function _clearWriterProposal() internal {
        pendingWriter = address(0);
        pendingWriterReleaseCommitment = bytes32(0);
        pendingWriterActivatesAt = 0;
    }
}
