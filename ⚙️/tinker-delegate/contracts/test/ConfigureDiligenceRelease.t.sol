// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ConfigureDiligenceReleaseScript} from "../script/ConfigureDiligenceRelease.s.sol";
import {DiligenceRoom} from "../src/DiligenceRoom.sol";

contract ConfigureDiligenceReleaseHarness is ConfigureDiligenceReleaseScript {
    function executeConfiguredPhase(uint256 phase, ReleaseInputs memory inputs) external {
        _executePhase(phase, inputs);
    }
}

contract ConfigureDiligenceReleaseTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    ConfigureDiligenceReleaseHarness internal script;
    DiligenceRoom internal room;
    address internal operator;
    address internal verifier = makeAddr("independent-diligence-verifier");
    address internal attestationVerifier = makeAddr("independent-diligence-qvl");
    address internal tee = makeAddr("diligence-tee");
    bytes32 internal compose = keccak256("diligence-release-compose");
    bytes32 internal qvlReleasePolicyHash = keccak256("diligence-qvl-release-policy");
    bytes32 internal evaluatorPolicyOne = keccak256("diligence-evaluator-policy-one");
    bytes32 internal evaluatorPolicyTwo = keccak256("diligence-evaluator-policy-two");
    bytes32 internal evaluatorPolicyThree = keccak256("diligence-evaluator-policy-three");
    bytes32 internal evaluatorPolicySetRoot;

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        vm.startPrank(operator);
        room = new DiligenceRoom(true);
        room.freezeFeeBps();
        room.enableComputeSettlementPolicy();
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();
        vm.stopPrank();
        evaluatorPolicySetRoot =
            room.computeEvaluatorPolicySetRoot([evaluatorPolicyOne, evaluatorPolicyTwo, evaluatorPolicyThree]);
        script = new ConfigureDiligenceReleaseHarness();
    }

    function test_ThreeTimelockedPhasesProduceExactClosedRelease() public {
        _runPhase(1);
        assertEq(room.pendingComposeCount(), 1);
        assertEq(room.approvedComposeCount(), 0);
        assertGt(room.pendingComposeActivations(compose), block.timestamp);
        assertEq(room.pendingAttestationVerifier(), attestationVerifier);
        assertEq(room.pendingAttestationReleasePolicyHash(), qvlReleasePolicyHash);
        assertEq(room.pendingEvaluatorPolicyCount(), 3);
        assertEq(room.approvedEvaluatorPolicyCount(), 0);

        uint256 composeActivatesAt = room.pendingComposeActivations(compose);
        uint256 qvlActivatesAt = room.pendingAttestationBindingActivatesAt();
        vm.warp(composeActivatesAt > qvlActivatesAt ? composeActivatesAt : qvlActivatesAt);
        _runPhase(2);
        assertEq(room.approvedComposeCount(), 1);
        assertEq(room.pendingComposeCount(), 0);
        assertEq(room.pendingTeeIdentityCount(), 1);
        assertEq(room.approvedTeeIdentityCount(), 0);
        assertEq(room.pendingTeeIdentityComposeHash(tee), compose);
        assertEq(room.attestationVerifier(), attestationVerifier);
        assertEq(room.attestationReleasePolicyHash(), qvlReleasePolicyHash);
        assertTrue(room.attestationBindingFrozen());
        assertEq(room.pendingEvaluatorPolicyCount(), 0);
        assertEq(room.approvedEvaluatorPolicyCount(), 3);
        assertFalse(room.evaluatorPolicySetFrozen());

        vm.warp(room.pendingTeeIdentityActivations(tee));
        _runPhase(3);
        assertEq(room.approvedComposeCount(), 1);
        assertEq(room.approvedTeeIdentityCount(), 1);
        assertEq(room.pendingComposeCount(), 0);
        assertEq(room.pendingTeeIdentityCount(), 0);
        assertTrue(room.composeAdditionsFrozen());
        assertTrue(room.teeIdentityAdditionsFrozen());
        assertEq(room.teeIdentityComposeHash(tee), compose);
        assertTrue(room.evaluatorPolicySetFrozen());
        assertEq(room.evaluatorPolicySetRoot(), _evaluatorPolicySetRoot());
    }

    function test_CannotSkipTimelocksOrReplayPhases() public {
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 admission state"));
        _runPhase(2);
        _runPhase(1);
        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-admission room"));
        _runPhase(1);
        vm.expectRevert(bytes("compose timelock has not elapsed"));
        _runPhase(2);
    }

    function test_ExtraAdmissionBlocksExactReleaseClosure() public {
        _runPhase(1);
        vm.warp(room.pendingComposeActivations(compose));
        _runPhase(2);

        bytes32 extraCompose = keccak256("unreviewed-compose");
        vm.prank(operator);
        room.proposeComposeHash(extraCompose);
        uint256 teeActivatesAt = room.pendingTeeIdentityActivations(tee);
        uint256 extraActivatesAt = room.pendingComposeActivations(extraCompose);
        vm.warp(teeActivatesAt > extraActivatesAt ? teeActivatesAt : extraActivatesAt);
        vm.prank(operator);
        room.activateComposeHash(extraCompose);

        vm.expectRevert(bytes("phase 3 requires the exact phase-2 admission state"));
        _runPhase(3);
        assertFalse(room.composeAdditionsFrozen());
        assertFalse(room.teeIdentityAdditionsFrozen());
    }

    function test_PhaseThreeRejectsDriftedFrozenVerifierAuthority() public {
        _runPhase(1);
        uint256 composeActivatesAt = room.pendingComposeActivations(compose);
        uint256 qvlActivatesAt = room.pendingAttestationBindingActivatesAt();
        vm.warp(composeActivatesAt > qvlActivatesAt ? composeActivatesAt : qvlActivatesAt);
        _runPhase(2);
        vm.warp(room.pendingTeeIdentityActivations(tee));

        ConfigureDiligenceReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.resultVerifier = makeAddr("unreviewed-result-verifier");
        vm.expectRevert(bytes("phase 3 requires the exact phase-2 admission state"));
        script.executeConfiguredPhase(3, inputs);

        inputs = _inputs();
        inputs.attestationVerifier = makeAddr("unreviewed-attestation-verifier");
        vm.expectRevert(bytes("phase 3 requires the exact phase-2 admission state"));
        script.executeConfiguredPhase(3, inputs);

        inputs = _inputs();
        inputs.qvlReleasePolicyHash = keccak256("unreviewed-qvl-release-policy");
        vm.expectRevert(bytes("phase 3 requires the exact phase-2 admission state"));
        script.executeConfiguredPhase(3, inputs);
    }

    function test_PhaseThreeRejectsEvaluatorSetDriftBeforeAnyIrreversibleCall() public {
        _runPhase(1);
        uint256 composeActivatesAt = room.pendingComposeActivations(compose);
        uint256 qvlActivatesAt = room.pendingAttestationBindingActivatesAt();
        vm.warp(composeActivatesAt > qvlActivatesAt ? composeActivatesAt : qvlActivatesAt);
        _runPhase(2);

        bytes32 unreviewedPolicy = keccak256("unreviewed-evaluator-policy");
        vm.startPrank(operator);
        room.removeEvaluatorPolicy(evaluatorPolicyOne);
        room.proposeEvaluatorPolicy(unreviewedPolicy);
        vm.stopPrank();
        uint256 evaluatorActivatesAt = room.pendingEvaluatorPolicyActivations(unreviewedPolicy);
        uint256 teeActivatesAt = room.pendingTeeIdentityActivations(tee);
        vm.warp(evaluatorActivatesAt > teeActivatesAt ? evaluatorActivatesAt : teeActivatesAt);
        vm.prank(operator);
        room.activateEvaluatorPolicy(unreviewedPolicy);

        vm.expectRevert(bytes("phase 3 requires the exact phase-2 admission state"));
        _runPhase(3);
        assertEq(room.teeIdentityComposeHash(tee), bytes32(0));
        assertFalse(room.evaluatorPolicySetFrozen());
        assertFalse(room.composeAdditionsFrozen());
        assertFalse(room.teeIdentityAdditionsFrozen());
    }

    function test_RuntimeAndRolePinsAreRequired() public {
        ConfigureDiligenceReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.roomRuntimeCodeHash = keccak256("wrong-runtime");
        vm.expectRevert(bytes("DiligenceRoom runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.operator = makeAddr("wrong-operator");
        vm.expectRevert(bytes("operator does not own DiligenceRoom"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.teeIdentity = verifier;
        vm.expectRevert(bytes("diligence TEE conflicts with a control role"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.attestationVerifier = tee;
        vm.expectRevert(bytes("diligence attestation verifier conflicts with a release role"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.evaluatorPolicies[2] = inputs.evaluatorPolicies[1];
        vm.expectRevert(bytes("diligence evaluator policies must be distinct"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.evaluatorPolicySetRoot = keccak256("wrong-evaluator-policy-root");
        vm.expectRevert(bytes("diligence evaluator policy root mismatch"));
        script.executeConfiguredPhase(1, inputs);
    }

    function test_ReleaseRequiresFrozenLifecyclePolicy() public {
        vm.prank(operator);
        DiligenceRoom unfrozenRoom = new DiligenceRoom(true);
        ConfigureDiligenceReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.room = unfrozenRoom;
        inputs.roomRuntimeCodeHash = address(unfrozenRoom).codehash;
        vm.expectRevert(bytes("diligence fee is not release-frozen"));
        script.executeConfiguredPhase(1, inputs);
    }

    function _runPhase(uint256 phase) internal {
        script.executeConfiguredPhase(phase, _inputs());
    }

    function _inputs() internal view returns (ConfigureDiligenceReleaseScript.ReleaseInputs memory) {
        return ConfigureDiligenceReleaseScript.ReleaseInputs({
            room: room,
            roomRuntimeCodeHash: address(room).codehash,
            operator: operator,
            resultVerifier: verifier,
            teeIdentity: tee,
            composeHash: compose,
            attestationVerifier: attestationVerifier,
            qvlReleasePolicyHash: qvlReleasePolicyHash,
            evaluatorPolicies: [evaluatorPolicyOne, evaluatorPolicyTwo, evaluatorPolicyThree],
            evaluatorPolicySetRoot: evaluatorPolicySetRoot
        });
    }

    function _evaluatorPolicySetRoot() internal view returns (bytes32) {
        return evaluatorPolicySetRoot;
    }
}
