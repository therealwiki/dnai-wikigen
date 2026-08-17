// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";
import {RoyaltyDistributor} from "../src/RoyaltyDistributor.sol";

/// @notice Two-phase activation of the authoritative Collaboration royalty rail.
/// @dev The policy anchor must already have its third, distinct writer frozen
///      and unpaused. Phase 1 stages the exact settlement-CVM/QVL/anchor binding.
///      Phase 2 activates it after two days and only then unpauses settlement.
contract ConfigureRoyaltyReleaseScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    struct ReleaseInputs {
        RoyaltyDistributor distributor;
        bytes32 distributorRuntimeCodeHash;
        address operator;
        address settlementVerifier;
        address qvlVerifier;
        ExecutionPolicyAnchor anchor;
        bytes32 anchorRuntimeCodeHash;
        bytes32 anchorWriterReleaseCommitment;
    }

    function run() public {
        _runPhase(vm.envUint("ROYALTY_RELEASE_PHASE"));
    }

    function runPhase(uint256 phase) public {
        _runPhase(phase);
    }

    function _runPhase(uint256 phase) internal {
        ReleaseInputs memory inputs = ReleaseInputs({
            distributor: RoyaltyDistributor(payable(vm.envAddress("ROYALTY_DISTRIBUTOR_ADDRESS"))),
            distributorRuntimeCodeHash: vm.envBytes32("ROYALTY_DISTRIBUTOR_RUNTIME_CODE_HASH"),
            operator: vm.envAddress("DEPLOYMENT_OPERATOR"),
            settlementVerifier: vm.envAddress("ROYALTY_SETTLEMENT_VERIFIER"),
            qvlVerifier: vm.envAddress("ROYALTY_QVL_VERIFIER"),
            anchor: ExecutionPolicyAnchor(vm.envAddress("EXECUTION_POLICY_ANCHOR_ADDRESS")),
            anchorRuntimeCodeHash: vm.envBytes32("EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH"),
            anchorWriterReleaseCommitment: vm.envBytes32("EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT")
        });
        _executePhase(phase, inputs);
    }

    function _executePhase(uint256 phase, ReleaseInputs memory inputs) internal {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "royalty release is Base Sepolia only");
        _requireCommonInputs(inputs);
        if (phase == 1) _phaseOne(inputs);
        else if (phase == 2) _phaseTwo(inputs);
        else revert("ROYALTY_RELEASE_PHASE must be 1 or 2");

        console.log("Royalty release phase:", phase);
        console.log("RoyaltyDistributor:", address(inputs.distributor));
        console.log("Authority nonce:", inputs.distributor.authorityNonce());
        console.log("Paused:", inputs.distributor.paused());
    }

    function _requireCommonInputs(ReleaseInputs memory inputs) internal view {
        RoyaltyDistributor distributor = inputs.distributor;
        require(
            inputs.distributorRuntimeCodeHash != bytes32(0)
                && address(distributor).codehash == inputs.distributorRuntimeCodeHash,
            "RoyaltyDistributor runtime code hash mismatch"
        );
        require(
            inputs.operator != address(0) && distributor.owner() == inputs.operator,
            "operator does not own royalty rail"
        );
        require(distributor.pendingOwner() == address(0), "royalty rail has a pending owner");
        require(distributor.paused(), "RoyaltyDistributor must remain paused during admission");
        require(
            inputs.anchorRuntimeCodeHash != bytes32(0)
                && address(inputs.anchor).codehash == inputs.anchorRuntimeCodeHash,
            "ExecutionPolicyAnchor runtime code hash mismatch"
        );
        require(inputs.anchor.writerRotationsFrozen() && !inputs.anchor.paused(), "policy anchor release is not active");
        require(
            inputs.anchor.writerReleaseCommitment() == inputs.anchorWriterReleaseCommitment
                && inputs.anchorWriterReleaseCommitment != bytes32(0),
            "policy anchor release commitment mismatch"
        );
        address anchorWriter = inputs.anchor.writer();
        require(
            inputs.settlementVerifier != address(0) && inputs.qvlVerifier != address(0)
                && inputs.settlementVerifier != inputs.qvlVerifier,
            "royalty release signers must be nonzero and distinct"
        );
        require(
            inputs.settlementVerifier != inputs.operator && inputs.qvlVerifier != inputs.operator
                && inputs.settlementVerifier != address(distributor) && inputs.qvlVerifier != address(distributor)
                && inputs.settlementVerifier != address(inputs.anchor) && inputs.qvlVerifier != address(inputs.anchor)
                && anchorWriter != inputs.operator && anchorWriter != address(distributor)
                && anchorWriter != inputs.settlementVerifier && anchorWriter != inputs.qvlVerifier
                && anchorWriter != address(inputs.anchor),
            "royalty release roles must remain distinct"
        );
    }

    function _phaseOne(ReleaseInputs memory inputs) internal {
        RoyaltyDistributor distributor = inputs.distributor;
        require(
            distributor.authorityNonce() == 0 && distributor.settlementVerifier() == address(0)
                && distributor.qvlVerifier() == address(0) && distributor.executionPolicyAnchor() == address(0)
                && distributor.anchorWriterReleaseCommitment() == bytes32(0)
                && distributor.releasePolicyCommitment() == bytes32(0) && _authorityProposalIsEmpty(distributor),
            "phase 1 requires the exact fresh empty royalty authority"
        );

        vm.startBroadcast();
        distributor.proposeAuthorityBinding(
            inputs.settlementVerifier, inputs.qvlVerifier, address(inputs.anchor), inputs.anchorWriterReleaseCommitment
        );
        vm.stopBroadcast();

        bytes32 expectedPolicy = distributor.computeReleasePolicyCommitment(
            1,
            inputs.settlementVerifier,
            inputs.qvlVerifier,
            address(inputs.anchor),
            inputs.anchorWriterReleaseCommitment
        );
        require(
            distributor.pendingSettlementVerifier() == inputs.settlementVerifier
                && distributor.pendingQvlVerifier() == inputs.qvlVerifier
                && distributor.pendingExecutionPolicyAnchor() == address(inputs.anchor)
                && distributor.pendingAnchorWriterReleaseCommitment() == inputs.anchorWriterReleaseCommitment
                && distributor.pendingReleasePolicyCommitment() == expectedPolicy
                && distributor.pendingAuthorityNonce() == 1
                && distributor.pendingAuthorityActivatesAt() > block.timestamp
                && !distributor.pendingAuthorityRevocation() && distributor.paused(),
            "phase 1 did not stage the exact royalty release"
        );
    }

    function _phaseTwo(ReleaseInputs memory inputs) internal {
        RoyaltyDistributor distributor = inputs.distributor;
        bytes32 expectedPolicy = distributor.computeReleasePolicyCommitment(
            1,
            inputs.settlementVerifier,
            inputs.qvlVerifier,
            address(inputs.anchor),
            inputs.anchorWriterReleaseCommitment
        );

        bool proposalIsStaged = distributor.authorityNonce() == 0 && distributor.settlementVerifier() == address(0)
            && distributor.qvlVerifier() == address(0) && distributor.executionPolicyAnchor() == address(0)
            && distributor.anchorWriterReleaseCommitment() == bytes32(0)
            && distributor.releasePolicyCommitment() == bytes32(0)
            && distributor.pendingSettlementVerifier() == inputs.settlementVerifier
            && distributor.pendingQvlVerifier() == inputs.qvlVerifier
            && distributor.pendingExecutionPolicyAnchor() == address(inputs.anchor)
            && distributor.pendingAnchorWriterReleaseCommitment() == inputs.anchorWriterReleaseCommitment
            && distributor.pendingReleasePolicyCommitment() == expectedPolicy
            && distributor.pendingAuthorityNonce() == 1 && distributor.pendingAuthorityActivatesAt() != 0
            && !distributor.pendingAuthorityRevocation();
        bool proposalAlreadyActivated = distributor.authorityNonce() == 1
            && distributor.settlementVerifier() == inputs.settlementVerifier
            && distributor.qvlVerifier() == inputs.qvlVerifier
            && distributor.executionPolicyAnchor() == address(inputs.anchor)
            && distributor.anchorWriterReleaseCommitment() == inputs.anchorWriterReleaseCommitment
            && distributor.releasePolicyCommitment() == expectedPolicy && _authorityProposalIsEmpty(distributor)
            && distributor.settlementVerifierEverConfigured(inputs.settlementVerifier)
            && distributor.qvlVerifierEverConfigured(inputs.qvlVerifier)
            && distributor.anchorWriterEverConfigured(inputs.anchor.writer());
        require(
            proposalIsStaged || proposalAlreadyActivated,
            "phase 2 requires the exact staged or active-paused royalty release"
        );
        if (proposalIsStaged) {
            require(
                distributor.pendingAuthorityActivatesAt() <= block.timestamp,
                "royalty authority timelock has not elapsed"
            );
        }

        vm.startBroadcast();
        if (proposalIsStaged) distributor.activateAuthorityProposal();
        distributor.setPaused(false);
        vm.stopBroadcast();

        require(
            distributor.authorityNonce() == 1 && distributor.settlementVerifier() == inputs.settlementVerifier
                && distributor.qvlVerifier() == inputs.qvlVerifier
                && distributor.executionPolicyAnchor() == address(inputs.anchor)
                && distributor.anchorWriterReleaseCommitment() == inputs.anchorWriterReleaseCommitment
                && distributor.releasePolicyCommitment() == expectedPolicy && _authorityProposalIsEmpty(distributor)
                && distributor.pendingOwner() == address(0) && !distributor.paused(),
            "phase 2 did not activate the exact royalty release"
        );
    }

    function _authorityProposalIsEmpty(RoyaltyDistributor distributor) internal view returns (bool) {
        return distributor.pendingSettlementVerifier() == address(0) && distributor.pendingQvlVerifier() == address(0)
            && distributor.pendingExecutionPolicyAnchor() == address(0)
            && distributor.pendingAnchorWriterReleaseCommitment() == bytes32(0)
            && distributor.pendingReleasePolicyCommitment() == bytes32(0) && distributor.pendingAuthorityNonce() == 0
            && distributor.pendingAuthorityActivatesAt() == 0 && !distributor.pendingAuthorityRevocation();
    }
}
