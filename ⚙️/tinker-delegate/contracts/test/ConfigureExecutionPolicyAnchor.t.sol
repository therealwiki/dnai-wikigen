// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ConfigureExecutionPolicyAnchorScript} from "../script/ConfigureExecutionPolicyAnchor.s.sol";
import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";

contract ConfigureExecutionPolicyAnchorHarness is ConfigureExecutionPolicyAnchorScript {
    function executeConfiguredPhase(uint256 phase, ReleaseInputs memory inputs) external {
        _executePhase(phase, inputs);
    }
}

contract ConfigureExecutionPolicyAnchorTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    address internal operator;
    address internal writer = makeAddr("policy-anchor-cvm-writer");
    bytes32 internal releaseCommitment = keccak256("policy-anchor-release");

    ConfigureExecutionPolicyAnchorHarness internal script;
    ExecutionPolicyAnchor internal anchor;

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        anchor = new ExecutionPolicyAnchor(
            operator, keccak256("deployment-intent-sha256"), keccak256("reviewer-authority-genesis-sha256")
        );
        script = new ConfigureExecutionPolicyAnchorHarness();
    }

    function test_TwoTimelockedPhasesProduceExactFrozenLiveRelease() public {
        _runPhase(1);
        assertEq(anchor.writer(), address(0));
        assertEq(anchor.pendingWriter(), writer);
        assertEq(anchor.pendingWriterReleaseCommitment(), releaseCommitment);
        assertGt(anchor.pendingWriterActivatesAt(), block.timestamp);
        assertTrue(anchor.paused());

        vm.warp(anchor.pendingWriterActivatesAt());
        _runPhase(2);
        assertEq(anchor.writer(), writer);
        assertEq(anchor.writerReleaseCommitment(), releaseCommitment);
        assertEq(anchor.pendingWriter(), address(0));
        assertEq(anchor.pendingWriterActivatesAt(), 0);
        assertTrue(anchor.writerRotationsFrozen());
        assertFalse(anchor.paused());
        assertEq(anchor.globalSequence(), 0);
        assertEq(anchor.globalHead(), bytes32(0));
    }

    function test_CannotSkipTimelockOrReplayEitherPhase() public {
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 writer proposal"));
        _runPhase(2);

        _runPhase(1);
        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-writer anchor"));
        _runPhase(1);
        vm.expectRevert(bytes("writer timelock has not elapsed"));
        _runPhase(2);

        vm.warp(anchor.pendingWriterActivatesAt());
        _runPhase(2);
        vm.expectRevert(bytes("anchor must remain paused during release admission"));
        _runPhase(2);
    }

    function test_RuntimeOwnerAndRolePinsAreRequired() public {
        ConfigureExecutionPolicyAnchorScript.ReleaseInputs memory inputs = _inputs();
        inputs.anchorRuntimeCodeHash = keccak256("wrong-runtime");
        vm.expectRevert(bytes("ExecutionPolicyAnchor runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.operator = makeAddr("wrong-owner");
        vm.expectRevert(bytes("operator does not own anchor"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.writer = operator;
        vm.expectRevert(bytes("policy-anchor writer conflicts with a control role"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.writerReleaseCommitment = bytes32(0);
        vm.expectRevert(bytes("writer release commitment must be nonzero"));
        script.executeConfiguredPhase(1, inputs);
    }

    function test_UnexpectedPendingWriterBlocksReviewedRelease() public {
        address otherWriter = makeAddr("unreviewed-writer");
        vm.prank(operator);
        anchor.proposeWriter(otherWriter, keccak256("unreviewed-release"));

        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-writer anchor"));
        _runPhase(1);
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 writer proposal"));
        _runPhase(2);
    }

    function test_ExistingDecisionBlocksReleaseConfigurator() public {
        _runPhase(1);
        vm.warp(anchor.pendingWriterActivatesAt());
        _runPhase(2);
        vm.prank(writer);
        anchor.anchorDecision(
            0, bytes32(0), keccak256("resource"), bytes32(0), keccak256("decision"), releaseCommitment
        );

        vm.prank(operator);
        anchor.setPaused(true);
        vm.expectRevert(bytes("anchor already contains decisions"));
        _runPhase(2);
    }

    function _runPhase(uint256 phase) internal {
        script.executeConfiguredPhase(phase, _inputs());
    }

    function _inputs() internal view returns (ConfigureExecutionPolicyAnchorScript.ReleaseInputs memory) {
        return ConfigureExecutionPolicyAnchorScript.ReleaseInputs({
            anchor: anchor,
            anchorRuntimeCodeHash: address(anchor).codehash,
            operator: operator,
            writer: writer,
            writerReleaseCommitment: releaseCommitment
        });
    }
}
