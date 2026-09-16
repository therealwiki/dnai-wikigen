// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";

/// @notice Two-phase admission of the exact release-bound policy-anchor writer.
/// @dev Phase 1 proposes the writer/release pair. Phase 2 activates it after
///      two days, permanently freezes writer rotations, and unpauses anchoring.
///      Both phases require a pristine anchor with no decisions.
contract ConfigureExecutionPolicyAnchorScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    struct ReleaseInputs {
        ExecutionPolicyAnchor anchor;
        bytes32 anchorRuntimeCodeHash;
        address operator;
        address writer;
        bytes32 writerReleaseCommitment;
    }

    function run() public {
        _runPhase(vm.envUint("EXECUTION_POLICY_ANCHOR_RELEASE_PHASE"));
    }

    function runPhase(uint256 phase) public {
        _runPhase(phase);
    }

    function _runPhase(uint256 phase) internal {
        ReleaseInputs memory inputs = ReleaseInputs({
            anchor: ExecutionPolicyAnchor(vm.envAddress("EXECUTION_POLICY_ANCHOR_ADDRESS")),
            anchorRuntimeCodeHash: vm.envBytes32("EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH"),
            operator: vm.envAddress("DEPLOYMENT_OPERATOR"),
            writer: vm.envAddress("EXECUTION_POLICY_ANCHOR_WRITER"),
            writerReleaseCommitment: vm.envBytes32("EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT")
        });
        _executePhase(phase, inputs);
    }

    function _executePhase(uint256 phase, ReleaseInputs memory inputs) internal {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "policy-anchor release is Base Sepolia only");
        _requireCommonReleaseInputs(inputs);

        if (phase == 1) _phaseOne(inputs);
        else if (phase == 2) _phaseTwo(inputs);
        else revert("EXECUTION_POLICY_ANCHOR_RELEASE_PHASE must be 1 or 2");

        console.log("Execution-policy anchor release phase:", phase);
        console.log("ExecutionPolicyAnchor:", address(inputs.anchor));
        console.log("Writer:", inputs.anchor.writer());
        console.log("Global sequence:", inputs.anchor.globalSequence());
        console.log("Paused:", inputs.anchor.paused());
        console.log("Writer rotations frozen:", inputs.anchor.writerRotationsFrozen());
    }

    function _requireCommonReleaseInputs(ReleaseInputs memory inputs) internal view {
        ExecutionPolicyAnchor anchor = inputs.anchor;
        require(
            inputs.anchorRuntimeCodeHash != bytes32(0) && address(anchor).codehash == inputs.anchorRuntimeCodeHash,
            "ExecutionPolicyAnchor runtime code hash mismatch"
        );
        require(inputs.operator != address(0) && anchor.owner() == inputs.operator, "operator does not own anchor");
        require(inputs.writer != address(0), "policy-anchor writer must be nonzero");
        require(
            inputs.writer != inputs.operator && inputs.writer != address(anchor),
            "policy-anchor writer conflicts with a control role"
        );
        require(inputs.writerReleaseCommitment != bytes32(0), "writer release commitment must be nonzero");
        require(anchor.globalSequence() == 0 && anchor.globalHead() == bytes32(0), "anchor already contains decisions");
        require(anchor.paused(), "anchor must remain paused during release admission");
    }

    function _phaseOne(ReleaseInputs memory inputs) internal {
        ExecutionPolicyAnchor anchor = inputs.anchor;
        require(
            anchor.writer() == address(0) && anchor.writerReleaseCommitment() == bytes32(0)
                && anchor.pendingWriter() == address(0) && anchor.pendingWriterReleaseCommitment() == bytes32(0)
                && anchor.pendingWriterActivatesAt() == 0 && !anchor.writerRotationsFrozen(),
            "phase 1 requires the exact fresh empty-writer anchor"
        );

        vm.startBroadcast();
        anchor.proposeWriter(inputs.writer, inputs.writerReleaseCommitment);
        vm.stopBroadcast();

        require(
            anchor.writer() == address(0) && anchor.writerReleaseCommitment() == bytes32(0)
                && anchor.pendingWriter() == inputs.writer
                && anchor.pendingWriterReleaseCommitment() == inputs.writerReleaseCommitment
                && anchor.pendingWriterActivatesAt() > block.timestamp && !anchor.writerRotationsFrozen()
                && anchor.paused(),
            "phase 1 did not stage the exact writer release"
        );
    }

    function _phaseTwo(ReleaseInputs memory inputs) internal {
        ExecutionPolicyAnchor anchor = inputs.anchor;
        uint256 activatesAt = anchor.pendingWriterActivatesAt();
        require(
            anchor.writer() == address(0) && anchor.writerReleaseCommitment() == bytes32(0)
                && anchor.pendingWriter() == inputs.writer
                && anchor.pendingWriterReleaseCommitment() == inputs.writerReleaseCommitment && activatesAt != 0
                && !anchor.writerRotationsFrozen() && anchor.paused(),
            "phase 2 requires the exact phase-1 writer proposal"
        );
        require(activatesAt <= block.timestamp, "writer timelock has not elapsed");

        vm.startBroadcast();
        anchor.activateWriter();
        anchor.freezeWriterRotations();
        anchor.setPaused(false);
        vm.stopBroadcast();

        require(
            anchor.writer() == inputs.writer && anchor.writerReleaseCommitment() == inputs.writerReleaseCommitment
                && anchor.pendingWriter() == address(0) && anchor.pendingWriterReleaseCommitment() == bytes32(0)
                && anchor.pendingWriterActivatesAt() == 0 && anchor.writerRotationsFrozen() && !anchor.paused()
                && anchor.globalSequence() == 0 && anchor.globalHead() == bytes32(0),
            "phase 2 did not activate the exact frozen writer release"
        );
    }
}
