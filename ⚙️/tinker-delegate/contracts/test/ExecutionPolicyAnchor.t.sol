// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Test} from "forge-std/Test.sol";

import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";

contract ExecutionPolicyAnchorTest is Test {
    address internal owner = makeAddr("anchor-owner");
    address internal writer = makeAddr("release-bound-anchor-writer");
    address internal outsider = makeAddr("outsider");
    bytes32 internal releaseCommitment = keccak256("execution-policy-release-v1");
    bytes32 internal resource = keccak256("resource-a");
    bytes32 internal decision = keccak256("decision-a1");
    bytes32 internal deploymentIntentSha256 = keccak256("deployment-intent-sha256");
    bytes32 internal reviewerAuthorityGenesisAcceptanceSha256 =
        keccak256("reviewer-authority-genesis-acceptance-sha256");

    ExecutionPolicyAnchor internal anchor;

    event WriterProposed(address indexed writer, bytes32 indexed releaseCommitment, uint256 activatesAt);
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

    function setUp() public {
        anchor = new ExecutionPolicyAnchor(owner, deploymentIntentSha256, reviewerAuthorityGenesisAcceptanceSha256);
    }

    function test_InitialStateIsPausedAndHasNoWriterOrHeads() public view {
        assertEq(anchor.owner(), owner);
        assertEq(anchor.deploymentIntentSha256(), deploymentIntentSha256);
        assertEq(anchor.reviewerAuthorityGenesisAcceptanceSha256(), reviewerAuthorityGenesisAcceptanceSha256);
        assertEq(anchor.writer(), address(0));
        assertEq(anchor.writerReleaseCommitment(), bytes32(0));
        assertTrue(anchor.paused());
        assertFalse(anchor.writerRotationsFrozen());
        assertEq(anchor.globalSequence(), 0);
        assertEq(anchor.globalHead(), bytes32(0));
        assertEq(anchor.resourceDecisionHead(resource), bytes32(0));
        assertEq(anchor.resourceSequence(resource), 0);
        assertEq(anchor.decisionSequence(decision), 0);
    }

    function test_ConstructorRejectsZeroOwner() public {
        vm.expectRevert(ExecutionPolicyAnchor.ZeroAddress.selector);
        new ExecutionPolicyAnchor(address(0), deploymentIntentSha256, reviewerAuthorityGenesisAcceptanceSha256);
    }

    function test_ConstructorRejectsZeroAuthorityCommitments() public {
        vm.expectRevert(ExecutionPolicyAnchor.ZeroCommitment.selector);
        new ExecutionPolicyAnchor(owner, bytes32(0), reviewerAuthorityGenesisAcceptanceSha256);
        vm.expectRevert(ExecutionPolicyAnchor.ZeroCommitment.selector);
        new ExecutionPolicyAnchor(owner, deploymentIntentSha256, bytes32(0));
    }

    function test_WriterAdmissionIsTimelockedThenCanBePermanentlyFrozen() public {
        uint256 activatesAt = block.timestamp + anchor.WRITER_ROTATION_DELAY();
        vm.expectEmit(true, true, false, true, address(anchor));
        emit WriterProposed(writer, releaseCommitment, activatesAt);
        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);

        assertEq(anchor.pendingWriter(), writer);
        assertEq(anchor.pendingWriterReleaseCommitment(), releaseCommitment);
        assertEq(anchor.pendingWriterActivatesAt(), activatesAt);

        vm.expectRevert(abi.encodeWithSelector(ExecutionPolicyAnchor.TimelockNotElapsed.selector, activatesAt));
        vm.prank(owner);
        anchor.activateWriter();

        vm.warp(activatesAt);
        vm.expectEmit(true, true, true, true, address(anchor));
        emit WriterActivated(address(0), writer, releaseCommitment);
        vm.prank(owner);
        anchor.activateWriter();

        assertEq(anchor.writer(), writer);
        assertEq(anchor.writerReleaseCommitment(), releaseCommitment);
        assertEq(anchor.pendingWriter(), address(0));
        assertEq(anchor.pendingWriterReleaseCommitment(), bytes32(0));
        assertEq(anchor.pendingWriterActivatesAt(), 0);

        vm.expectEmit(true, true, false, true, address(anchor));
        emit WriterRotationsFrozen(writer, releaseCommitment);
        vm.prank(owner);
        anchor.freezeWriterRotations();
        assertTrue(anchor.writerRotationsFrozen());

        vm.expectRevert(ExecutionPolicyAnchor.WriterRotationsAreFrozen.selector);
        vm.prank(owner);
        anchor.proposeWriter(makeAddr("replacement"), keccak256("replacement-release"));
    }

    function test_CancelledWriterProposalCannotActivate() public {
        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);
        vm.prank(owner);
        anchor.cancelWriterProposal();

        assertEq(anchor.pendingWriter(), address(0));
        assertEq(anchor.pendingWriterReleaseCommitment(), bytes32(0));
        assertEq(anchor.pendingWriterActivatesAt(), 0);
        vm.expectRevert(ExecutionPolicyAnchor.ProposalMissing.selector);
        vm.prank(owner);
        anchor.activateWriter();
    }

    function test_WriterAndReleaseCanRotateOnlyWhilePausedBeforePermanentFreeze() public {
        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(owner);
        anchor.activateWriter();

        address replacement = makeAddr("replacement-writer");
        bytes32 replacementRelease = keccak256("replacement-release");
        vm.prank(owner);
        anchor.proposeWriter(replacement, replacementRelease);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(owner);
        anchor.activateWriter();

        assertEq(anchor.writer(), replacement);
        assertEq(anchor.writerReleaseCommitment(), replacementRelease);
        vm.prank(owner);
        anchor.freezeWriterRotations();
        vm.prank(owner);
        anchor.setPaused(false);

        vm.expectRevert(ExecutionPolicyAnchor.NotWriter.selector);
        vm.prank(writer);
        anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, releaseCommitment);
        vm.prank(replacement);
        anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, replacementRelease);
        assertEq(anchor.globalSequence(), 1);
    }

    function test_SameWriterCanBindNewReleaseBeforeFreezeButNotAfter() public {
        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(owner);
        anchor.activateWriter();

        bytes32 replacementRelease = keccak256("same-writer-new-release");
        vm.prank(owner);
        anchor.proposeWriter(writer, replacementRelease);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(owner);
        anchor.activateWriter();
        assertEq(anchor.writerReleaseCommitment(), replacementRelease);

        vm.prank(owner);
        anchor.freezeWriterRotations();
        vm.expectRevert(ExecutionPolicyAnchor.WriterRotationsAreFrozen.selector);
        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);
    }

    function test_WriterProposalValidatesAuthorityRolesAndCommitments() public {
        vm.expectRevert(ExecutionPolicyAnchor.NotOwner.selector);
        vm.prank(outsider);
        anchor.proposeWriter(writer, releaseCommitment);

        vm.expectRevert(ExecutionPolicyAnchor.ZeroAddress.selector);
        vm.prank(owner);
        anchor.proposeWriter(address(0), releaseCommitment);

        vm.expectRevert(ExecutionPolicyAnchor.ZeroCommitment.selector);
        vm.prank(owner);
        anchor.proposeWriter(writer, bytes32(0));

        vm.expectRevert(ExecutionPolicyAnchor.RoleConflict.selector);
        vm.prank(owner);
        anchor.proposeWriter(owner, releaseCommitment);

        vm.expectRevert(ExecutionPolicyAnchor.RoleConflict.selector);
        vm.prank(owner);
        anchor.proposeWriter(address(anchor), releaseCommitment);

        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);
        vm.expectRevert(ExecutionPolicyAnchor.ProposalExists.selector);
        vm.prank(owner);
        anchor.proposeWriter(makeAddr("other-writer"), keccak256("other-release"));
    }

    function test_UnpauseRequiresConfiguredFrozenWriterAndNoPendingProposal() public {
        vm.expectRevert(ExecutionPolicyAnchor.WriterNotConfigured.selector);
        vm.prank(owner);
        anchor.setPaused(false);

        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(owner);
        anchor.activateWriter();

        vm.expectRevert(ExecutionPolicyAnchor.WriterRotationsNotFrozen.selector);
        vm.prank(owner);
        anchor.setPaused(false);

        vm.prank(owner);
        anchor.proposeWriter(makeAddr("other-writer"), keccak256("other-release"));
        vm.expectRevert(ExecutionPolicyAnchor.PendingWriterProposal.selector);
        vm.prank(owner);
        anchor.freezeWriterRotations();
        vm.prank(owner);
        anchor.cancelWriterProposal();

        vm.prank(owner);
        anchor.freezeWriterRotations();
        vm.expectEmit(false, true, false, true, address(anchor));
        emit PauseSet(false, owner);
        vm.prank(owner);
        anchor.setPaused(false);
        assertFalse(anchor.paused());
    }

    function test_AnchorsExactGlobalAndResourceHeads() public {
        _configureRelease();
        bytes32 expectedHead =
            anchor.computeAnchorHead(1, bytes32(0), resource, bytes32(0), decision, writer, releaseCommitment);

        vm.expectEmit(true, true, true, true, address(anchor));
        emit DecisionAnchored(1, resource, decision, bytes32(0), expectedHead, bytes32(0), writer, releaseCommitment);
        vm.prank(writer);
        (uint256 newSequence, bytes32 newHead) =
            anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, releaseCommitment);

        assertEq(newSequence, 1);
        assertEq(newHead, expectedHead);
        assertEq(anchor.globalSequence(), 1);
        assertEq(anchor.globalHead(), expectedHead);
        assertEq(anchor.resourceDecisionHead(resource), decision);
        assertEq(anchor.resourceSequence(resource), 1);
        assertEq(anchor.decisionSequence(decision), 1);
    }

    function test_GlobalChainOrdersIndependentResourceHeads() public {
        _configureRelease();
        bytes32 resourceB = keccak256("resource-b");
        bytes32 decisionB = keccak256("decision-b1");

        vm.prank(writer);
        (, bytes32 headOne) = anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, releaseCommitment);
        bytes32 expectedHeadTwo =
            anchor.computeAnchorHead(2, headOne, resourceB, bytes32(0), decisionB, writer, releaseCommitment);
        vm.prank(writer);
        (, bytes32 headTwo) = anchor.anchorDecision(1, headOne, resourceB, bytes32(0), decisionB, releaseCommitment);

        assertEq(headTwo, expectedHeadTwo);
        assertEq(anchor.globalSequence(), 2);
        assertEq(anchor.resourceDecisionHead(resource), decision);
        assertEq(anchor.resourceSequence(resource), 1);
        assertEq(anchor.resourceDecisionHead(resourceB), decisionB);
        assertEq(anchor.resourceSequence(resourceB), 2);
    }

    function test_AppendRejectsWrongAuthorityReleaseAndEveryStaleCasInput() public {
        _configureRelease();

        vm.expectRevert(ExecutionPolicyAnchor.NotWriter.selector);
        vm.prank(outsider);
        anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, releaseCommitment);

        bytes32 wrongRelease = keccak256("wrong-release");
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionPolicyAnchor.UnexpectedWriterReleaseCommitment.selector, releaseCommitment, wrongRelease
            )
        );
        vm.prank(writer);
        anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, wrongRelease);

        vm.prank(writer);
        (, bytes32 headOne) = anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, releaseCommitment);
        bytes32 decisionTwo = keccak256("decision-a2");

        vm.expectRevert(abi.encodeWithSelector(ExecutionPolicyAnchor.UnexpectedGlobalSequence.selector, 1, 0));
        vm.prank(writer);
        anchor.anchorDecision(0, headOne, resource, decision, decisionTwo, releaseCommitment);

        vm.expectRevert(
            abi.encodeWithSelector(ExecutionPolicyAnchor.UnexpectedGlobalHead.selector, headOne, bytes32(0))
        );
        vm.prank(writer);
        anchor.anchorDecision(1, bytes32(0), resource, decision, decisionTwo, releaseCommitment);

        bytes32 staleResourceHead = keccak256("stale-resource-head");
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionPolicyAnchor.UnexpectedResourceHead.selector, resource, decision, staleResourceHead
            )
        );
        vm.prank(writer);
        anchor.anchorDecision(1, headOne, resource, staleResourceHead, decisionTwo, releaseCommitment);
    }

    function test_DecisionHashCannotReplayAcrossResources() public {
        _configureRelease();
        vm.prank(writer);
        (, bytes32 headOne) = anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, releaseCommitment);

        vm.expectRevert(abi.encodeWithSelector(ExecutionPolicyAnchor.DecisionAlreadyAnchored.selector, decision));
        vm.prank(writer);
        anchor.anchorDecision(1, headOne, keccak256("different-resource"), bytes32(0), decision, releaseCommitment);
        assertEq(anchor.globalSequence(), 1);
        assertEq(anchor.globalHead(), headOne);
    }

    function test_ZeroResourceAndDecisionCommitmentsFailClosed() public {
        _configureRelease();
        vm.expectRevert(ExecutionPolicyAnchor.ZeroCommitment.selector);
        vm.prank(writer);
        anchor.anchorDecision(0, bytes32(0), bytes32(0), bytes32(0), decision, releaseCommitment);

        vm.expectRevert(ExecutionPolicyAnchor.ZeroCommitment.selector);
        vm.prank(writer);
        anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), bytes32(0), releaseCommitment);
    }

    function test_NoNativeCustodyReceiveOrFallback() public {
        vm.deal(outsider, 1 ether);
        vm.prank(outsider);
        (bool receiveOk,) = address(anchor).call{value: 1 wei}("");
        assertFalse(receiveOk);

        vm.prank(outsider);
        (bool fallbackOk,) = address(anchor).call{value: 1 wei}(hex"deadbeef");
        assertFalse(fallbackOk);
        assertEq(address(anchor).balance, 0);
    }

    function test_WriterCanPauseButOnlyOwnerCanResume() public {
        _configureRelease();
        vm.prank(writer);
        anchor.setPaused(true);
        assertTrue(anchor.paused());

        vm.expectRevert(ExecutionPolicyAnchor.Paused.selector);
        vm.prank(writer);
        anchor.anchorDecision(0, bytes32(0), resource, bytes32(0), decision, releaseCommitment);

        vm.expectRevert(ExecutionPolicyAnchor.NotOwner.selector);
        vm.prank(writer);
        anchor.setPaused(false);

        vm.prank(owner);
        anchor.setPaused(false);
        assertFalse(anchor.paused());
    }

    function test_OwnershipTransferIsTwoStepAndCannotCollideWithWriter() public {
        _configureRelease();
        address newOwner = makeAddr("new-anchor-owner");

        vm.prank(owner);
        anchor.transferOwnership(newOwner);
        vm.expectRevert(ExecutionPolicyAnchor.NotPendingOwner.selector);
        vm.prank(outsider);
        anchor.acceptOwnership();

        vm.prank(newOwner);
        anchor.acceptOwnership();
        assertEq(anchor.owner(), newOwner);
        assertEq(anchor.pendingOwner(), address(0));

        vm.expectRevert(ExecutionPolicyAnchor.RoleConflict.selector);
        vm.prank(newOwner);
        anchor.transferOwnership(writer);
    }

    function testFuzz_MonotonicUpdatesPreserveExactLatestResourceHead(
        bytes32 fuzzResource,
        bytes32 firstDecision,
        bytes32 secondDecision
    ) public {
        vm.assume(fuzzResource != bytes32(0));
        vm.assume(firstDecision != bytes32(0));
        vm.assume(secondDecision != bytes32(0));
        vm.assume(firstDecision != secondDecision);
        _configureRelease();

        vm.prank(writer);
        (, bytes32 headOne) =
            anchor.anchorDecision(0, bytes32(0), fuzzResource, bytes32(0), firstDecision, releaseCommitment);
        bytes32 expectedHeadTwo = anchor.computeAnchorHead(
            2, headOne, fuzzResource, firstDecision, secondDecision, writer, releaseCommitment
        );
        vm.prank(writer);
        (, bytes32 headTwo) =
            anchor.anchorDecision(1, headOne, fuzzResource, firstDecision, secondDecision, releaseCommitment);

        assertEq(headTwo, expectedHeadTwo);
        assertEq(anchor.globalSequence(), 2);
        assertEq(anchor.resourceSequence(fuzzResource), 2);
        assertEq(anchor.resourceDecisionHead(fuzzResource), secondDecision);
        assertEq(anchor.decisionSequence(firstDecision), 1);
        assertEq(anchor.decisionSequence(secondDecision), 2);
    }

    function testFuzz_GlobalHeadDomainBindsContractWriterAndRelease(
        uint256 sequence,
        bytes32 priorGlobal,
        bytes32 fuzzResource,
        bytes32 priorResource,
        bytes32 fuzzDecision
    ) public {
        bytes32 baseline = anchor.computeAnchorHead(
            sequence, priorGlobal, fuzzResource, priorResource, fuzzDecision, writer, releaseCommitment
        );
        ExecutionPolicyAnchor otherAnchor =
            new ExecutionPolicyAnchor(owner, deploymentIntentSha256, reviewerAuthorityGenesisAcceptanceSha256);
        assertNotEq(
            baseline,
            otherAnchor.computeAnchorHead(
                sequence, priorGlobal, fuzzResource, priorResource, fuzzDecision, writer, releaseCommitment
            )
        );
        assertNotEq(
            baseline,
            anchor.computeAnchorHead(
                sequence, priorGlobal, fuzzResource, priorResource, fuzzDecision, outsider, releaseCommitment
            )
        );
        assertNotEq(
            baseline,
            anchor.computeAnchorHead(
                sequence,
                priorGlobal,
                fuzzResource,
                priorResource,
                fuzzDecision,
                writer,
                keccak256(abi.encode(releaseCommitment))
            )
        );
    }

    function _configureRelease() internal {
        vm.prank(owner);
        anchor.proposeWriter(writer, releaseCommitment);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(owner);
        anchor.activateWriter();
        vm.prank(owner);
        anchor.freezeWriterRotations();
        vm.prank(owner);
        anchor.setPaused(false);
    }
}

contract ExecutionPolicyAnchorHandler {
    ExecutionPolicyAnchor public immutable ANCHOR;
    bytes32[4] internal _resources;
    bytes32[4] internal _expectedResourceHeads;
    uint256[4] internal _expectedResourceSequences;
    bytes32 public immutable RELEASE_COMMITMENT;

    uint256 public expectedGlobalSequence;
    bytes32 public expectedGlobalHead;
    uint256 public decisionNonce;
    bytes32 public lastDecision;

    constructor(ExecutionPolicyAnchor target, bytes32 release) {
        ANCHOR = target;
        RELEASE_COMMITMENT = release;
        _resources[0] = keccak256("invariant-resource-0");
        _resources[1] = keccak256("invariant-resource-1");
        _resources[2] = keccak256("invariant-resource-2");
        _resources[3] = keccak256("invariant-resource-3");
    }

    function append(uint8 resourceIndex, bytes32 salt) external {
        uint256 index = uint256(resourceIndex) % _resources.length;
        bytes32 decision = keccak256(abi.encode("invariant-decision", decisionNonce, salt, _resources[index]));
        decisionNonce += 1;
        (uint256 newSequence, bytes32 newGlobalHead) = ANCHOR.anchorDecision(
            expectedGlobalSequence,
            expectedGlobalHead,
            _resources[index],
            _expectedResourceHeads[index],
            decision,
            RELEASE_COMMITMENT
        );
        expectedGlobalSequence = newSequence;
        expectedGlobalHead = newGlobalHead;
        _expectedResourceHeads[index] = decision;
        _expectedResourceSequences[index] = newSequence;
        lastDecision = decision;
    }

    function attemptStaleGlobalCas(uint8 resourceIndex, bytes32 salt) external {
        uint256 index = uint256(resourceIndex) % _resources.length;
        bytes32 proposedDecision = keccak256(abi.encode("stale", decisionNonce, salt));
        (bool ok,) = address(ANCHOR)
            .call(
                abi.encodeCall(
                    ExecutionPolicyAnchor.anchorDecision,
                    (
                        expectedGlobalSequence + 1,
                        expectedGlobalHead,
                        _resources[index],
                        _expectedResourceHeads[index],
                        proposedDecision,
                        RELEASE_COMMITMENT
                    )
                )
            );
        require(!ok, "stale global CAS unexpectedly succeeded");
    }

    function attemptDecisionReplay(uint8 resourceIndex) external {
        if (lastDecision == bytes32(0)) return;
        uint256 index = uint256(resourceIndex) % _resources.length;
        (bool ok,) = address(ANCHOR)
            .call(
                abi.encodeCall(
                    ExecutionPolicyAnchor.anchorDecision,
                    (
                        expectedGlobalSequence,
                        expectedGlobalHead,
                        _resources[index],
                        _expectedResourceHeads[index],
                        lastDecision,
                        RELEASE_COMMITMENT
                    )
                )
            );
        require(!ok, "decision replay unexpectedly succeeded");
    }

    function resource(uint256 index) external view returns (bytes32) {
        return _resources[index];
    }

    function expectedResourceHead(uint256 index) external view returns (bytes32) {
        return _expectedResourceHeads[index];
    }

    function expectedResourceSequence(uint256 index) external view returns (uint256) {
        return _expectedResourceSequences[index];
    }
}

contract ExecutionPolicyAnchorInvariantTest is StdInvariant, Test {
    address internal owner = makeAddr("invariant-anchor-owner");
    bytes32 internal releaseCommitment = keccak256("invariant-release");
    bytes32 internal deploymentIntentSha256 = keccak256("invariant-deployment-intent");
    bytes32 internal reviewerAuthorityGenesisAcceptanceSha256 = keccak256("invariant-reviewer-genesis-acceptance");

    ExecutionPolicyAnchor internal anchor;
    ExecutionPolicyAnchorHandler internal handler;

    function setUp() public {
        anchor = new ExecutionPolicyAnchor(owner, deploymentIntentSha256, reviewerAuthorityGenesisAcceptanceSha256);
        handler = new ExecutionPolicyAnchorHandler(anchor, releaseCommitment);

        vm.prank(owner);
        anchor.proposeWriter(address(handler), releaseCommitment);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(owner);
        anchor.activateWriter();
        vm.prank(owner);
        anchor.freezeWriterRotations();
        vm.prank(owner);
        anchor.setPaused(false);

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = handler.append.selector;
        selectors[1] = handler.attemptStaleGlobalCas.selector;
        selectors[2] = handler.attemptDecisionReplay.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function invariant_GlobalSequenceAndHeadNeverDivergeFromSuccessfulAppends() public view {
        assertEq(anchor.globalSequence(), handler.expectedGlobalSequence());
        assertEq(anchor.globalHead(), handler.expectedGlobalHead());
    }

    function invariant_ResourceHeadsAndSequencesNeverRegress() public view {
        for (uint256 index = 0; index < 4; index++) {
            bytes32 resourceHash = handler.resource(index);
            bytes32 expectedHead = handler.expectedResourceHead(index);
            uint256 expectedSequence = handler.expectedResourceSequence(index);
            assertEq(anchor.resourceDecisionHead(resourceHash), expectedHead);
            assertEq(anchor.resourceSequence(resourceHash), expectedSequence);
            assertLe(expectedSequence, anchor.globalSequence());
            if (expectedHead == bytes32(0)) assertEq(expectedSequence, 0);
            else assertEq(anchor.decisionSequence(expectedHead), expectedSequence);
        }
    }

    function invariant_ReleaseAuthorityRemainsFrozenAndUnpaused() public view {
        assertEq(anchor.writer(), address(handler));
        assertEq(anchor.writerReleaseCommitment(), releaseCommitment);
        assertTrue(anchor.writerRotationsFrozen());
        assertFalse(anchor.paused());
        assertEq(anchor.pendingWriter(), address(0));
        assertEq(anchor.pendingWriterActivatesAt(), 0);
    }
}
