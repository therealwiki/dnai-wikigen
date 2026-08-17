// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ConfigureRoyaltyReleaseScript} from "../script/ConfigureRoyaltyRelease.s.sol";
import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";
import {RoyaltyDistributor} from "../src/RoyaltyDistributor.sol";

contract ConfigureRoyaltyReleaseHarness is ConfigureRoyaltyReleaseScript {
    function executeConfiguredPhase(uint256 phase, ReleaseInputs memory inputs) external {
        _executePhase(phase, inputs);
    }
}

contract ConfigureRoyaltyReleaseTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    address internal operator;
    address internal settlementVerifier = makeAddr("royalty-settlement-cvm");
    address internal qvlVerifier = makeAddr("royalty-independent-qvl");
    address internal anchorWriter = makeAddr("policy-anchor-writer");
    bytes32 internal anchorWriterRelease = keccak256("policy-anchor-release");

    ConfigureRoyaltyReleaseHarness internal script;
    ExecutionPolicyAnchor internal anchor;
    RoyaltyDistributor internal distributor;

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        anchor = new ExecutionPolicyAnchor(
            operator, keccak256("deployment-intent"), keccak256("reviewer-genesis-acceptance")
        );
        vm.prank(operator);
        anchor.proposeWriter(anchorWriter, anchorWriterRelease);
        vm.warp(anchor.pendingWriterActivatesAt());
        vm.prank(operator);
        anchor.activateWriter();
        vm.prank(operator);
        anchor.freezeWriterRotations();
        vm.prank(operator);
        anchor.setPaused(false);
        distributor = new RoyaltyDistributor(operator);
        script = new ConfigureRoyaltyReleaseHarness();
    }

    function test_TwoTimelockedPhasesProduceExactLiveRelease() public {
        _runPhase(1);
        assertEq(distributor.settlementVerifier(), address(0));
        assertEq(distributor.pendingSettlementVerifier(), settlementVerifier);
        assertEq(distributor.pendingQvlVerifier(), qvlVerifier);
        assertEq(distributor.pendingExecutionPolicyAnchor(), address(anchor));
        assertTrue(distributor.paused());

        vm.warp(distributor.pendingAuthorityActivatesAt());
        _runPhase(2);
        assertEq(distributor.authorityNonce(), 1);
        assertEq(distributor.settlementVerifier(), settlementVerifier);
        assertEq(distributor.qvlVerifier(), qvlVerifier);
        assertEq(distributor.executionPolicyAnchor(), address(anchor));
        assertEq(distributor.anchorWriterReleaseCommitment(), anchorWriterRelease);
        assertEq(distributor.pendingAuthorityActivatesAt(), 0);
        assertFalse(distributor.paused());
        assertTrue(distributor.settlementVerifierEverConfigured(settlementVerifier));
        assertTrue(distributor.qvlVerifierEverConfigured(qvlVerifier));
    }

    function test_CannotSkipTimelockOrReplayPhases() public {
        vm.expectRevert(bytes("phase 2 requires the exact staged or active-paused royalty release"));
        _runPhase(2);

        _runPhase(1);
        vm.expectRevert(bytes("phase 1 requires the exact fresh empty royalty authority"));
        _runPhase(1);
        vm.expectRevert(bytes("royalty authority timelock has not elapsed"));
        _runPhase(2);

        vm.warp(distributor.pendingAuthorityActivatesAt());
        _runPhase(2);
        vm.expectRevert(bytes("RoyaltyDistributor must remain paused during admission"));
        _runPhase(2);
    }

    function test_PhaseTwoRecoversAfterActivationMinedButUnpauseFailed() public {
        _runPhase(1);
        vm.warp(distributor.pendingAuthorityActivatesAt());

        vm.prank(operator);
        distributor.activateAuthorityProposal();
        assertEq(distributor.authorityNonce(), 1);
        assertEq(distributor.settlementVerifier(), settlementVerifier);
        assertEq(distributor.pendingAuthorityActivatesAt(), 0);
        assertTrue(distributor.paused());

        _runPhase(2);
        assertFalse(distributor.paused());
        assertEq(distributor.authorityNonce(), 1);
        assertEq(distributor.releasePolicyCommitment(), _expectedPolicy());
    }

    function test_PhaseTwoRejectsMutatedActivePausedPartialSuccess() public {
        _runPhase(1);
        vm.warp(distributor.pendingAuthorityActivatesAt());
        vm.prank(operator);
        distributor.activateAuthorityProposal();

        vm.prank(operator);
        distributor.proposeAuthorityBinding(
            makeAddr("unreviewed-settlement-cvm"),
            makeAddr("unreviewed-independent-qvl"),
            address(anchor),
            anchorWriterRelease
        );
        vm.expectRevert(bytes("phase 2 requires the exact staged or active-paused royalty release"));
        _runPhase(2);
        assertTrue(distributor.paused());
    }

    function test_PendingOwnerBlocksCeremonyAdmission() public {
        vm.prank(operator);
        distributor.transferOwnership(makeAddr("unreviewed-owner"));

        vm.expectRevert(bytes("royalty rail has a pending owner"));
        _runPhase(1);
    }

    function test_RuntimeOwnerAndRolePinsAreRequired() public {
        ConfigureRoyaltyReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.distributorRuntimeCodeHash = keccak256("wrong-distributor-runtime");
        vm.expectRevert(bytes("RoyaltyDistributor runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.anchorRuntimeCodeHash = keccak256("wrong-anchor-runtime");
        vm.expectRevert(bytes("ExecutionPolicyAnchor runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.operator = makeAddr("wrong-owner");
        vm.expectRevert(bytes("operator does not own royalty rail"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.qvlVerifier = settlementVerifier;
        vm.expectRevert(bytes("royalty release signers must be nonzero and distinct"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.settlementVerifier = anchorWriter;
        vm.expectRevert(bytes("royalty release roles must remain distinct"));
        script.executeConfiguredPhase(1, inputs);
    }

    function test_DistributorCannotBeConfiguredAsAnchorWriter() public {
        bytes32 release = keccak256("distributor-anchor-writer-release");
        ExecutionPolicyAnchor selfWriterAnchor = new ExecutionPolicyAnchor(
            operator, keccak256("self-writer-deployment"), keccak256("self-writer-reviewers")
        );
        vm.prank(operator);
        selfWriterAnchor.proposeWriter(address(distributor), release);
        vm.warp(selfWriterAnchor.pendingWriterActivatesAt());
        vm.prank(operator);
        selfWriterAnchor.activateWriter();
        vm.prank(operator);
        selfWriterAnchor.freezeWriterRotations();
        vm.prank(operator);
        selfWriterAnchor.setPaused(false);

        ConfigureRoyaltyReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.anchor = selfWriterAnchor;
        inputs.anchorRuntimeCodeHash = address(selfWriterAnchor).codehash;
        inputs.anchorWriterReleaseCommitment = release;

        vm.expectRevert(bytes("royalty release roles must remain distinct"));
        script.executeConfiguredPhase(1, inputs);
    }

    function test_AnchorPauseOrReleaseMismatchBlocksCeremony() public {
        vm.prank(anchorWriter);
        anchor.setPaused(true);
        vm.expectRevert(bytes("policy anchor release is not active"));
        _runPhase(1);

        vm.prank(operator);
        anchor.setPaused(false);
        ConfigureRoyaltyReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.anchorWriterReleaseCommitment = keccak256("wrong-release");
        vm.expectRevert(bytes("policy anchor release commitment mismatch"));
        script.executeConfiguredPhase(1, inputs);
    }

    function _runPhase(uint256 phase) internal {
        script.executeConfiguredPhase(phase, _inputs());
    }

    function _inputs() internal view returns (ConfigureRoyaltyReleaseScript.ReleaseInputs memory) {
        return ConfigureRoyaltyReleaseScript.ReleaseInputs({
            distributor: distributor,
            distributorRuntimeCodeHash: address(distributor).codehash,
            operator: operator,
            settlementVerifier: settlementVerifier,
            qvlVerifier: qvlVerifier,
            anchor: anchor,
            anchorRuntimeCodeHash: address(anchor).codehash,
            anchorWriterReleaseCommitment: anchorWriterRelease
        });
    }

    function _expectedPolicy() internal view returns (bytes32) {
        return distributor.computeReleasePolicyCommitment(
            1, settlementVerifier, qvlVerifier, address(anchor), anchorWriterRelease
        );
    }
}
