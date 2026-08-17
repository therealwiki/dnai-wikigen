// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {DiligenceRoom} from "../src/DiligenceRoom.sol";

/// @notice Four-phase admission of the exact release-bound diligence CVM and
///         delayed handoff to the reviewed permanent governance controller.
/// @dev Phase 1 proposes the compose hash. Phase 2 activates that hash and
///      proposes the TEE identity's exact binding. Phase 3 activates the
///      binding, permanently closes both admission sets, and proposes the
///      governance controller. Phase 4 is accepted by that controller after
///      the fixed transfer delay. The room remains fail-closed until phase 4.
contract ConfigureDiligenceReleaseScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    struct ReleaseInputs {
        DiligenceRoom room;
        bytes32 roomRuntimeCodeHash;
        address operator;
        address governanceController;
        address resultVerifier;
        address teeIdentity;
        bytes32 composeHash;
        address attestationVerifier;
        bytes32 qvlReleasePolicyHash;
        bytes32[3] evaluatorPolicies;
        bytes32 evaluatorPolicySetRoot;
    }

    function run() public {
        _runPhase(vm.envUint("DILIGENCE_RELEASE_PHASE"));
    }

    function runPhase(uint256 phase) public {
        _runPhase(phase);
    }

    function _runPhase(uint256 phase) internal {
        ReleaseInputs memory inputs = ReleaseInputs({
            room: DiligenceRoom(payable(vm.envAddress("DILIGENCE_ROOM_ADDRESS"))),
            roomRuntimeCodeHash: vm.envBytes32("DILIGENCE_RUNTIME_CODE_HASH"),
            operator: vm.envAddress("DEPLOYMENT_OPERATOR"),
            governanceController: vm.envAddress("DILIGENCE_GOVERNANCE_CONTROLLER"),
            resultVerifier: vm.envAddress("DILIGENCE_RESULT_VERIFIER"),
            teeIdentity: vm.envAddress("DILIGENCE_TEE_IDENTITY"),
            composeHash: vm.envBytes32("DILIGENCE_COMPOSE_HASH"),
            attestationVerifier: vm.envAddress("DILIGENCE_ATTESTATION_VERIFIER"),
            qvlReleasePolicyHash: vm.envBytes32("DILIGENCE_QVL_RELEASE_POLICY_HASH"),
            evaluatorPolicies: [
                vm.envBytes32("DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1"),
                vm.envBytes32("DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2"),
                vm.envBytes32("DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3")
            ],
            evaluatorPolicySetRoot: vm.envBytes32("DILIGENCE_EVALUATOR_POLICY_SET_ROOT")
        });
        _executePhase(phase, inputs);
    }

    function _executePhase(uint256 phase, ReleaseInputs memory inputs) internal {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "diligence release is Base Sepolia only");
        _requireCommonReleaseInputs(phase, inputs);

        if (phase == 1) {
            _phaseOne(
                inputs.room,
                inputs.resultVerifier,
                inputs.composeHash,
                inputs.attestationVerifier,
                inputs.qvlReleasePolicyHash,
                inputs.evaluatorPolicies
            );
        } else if (phase == 2) {
            _phaseTwo(
                inputs.room,
                inputs.teeIdentity,
                inputs.resultVerifier,
                inputs.composeHash,
                inputs.attestationVerifier,
                inputs.qvlReleasePolicyHash,
                inputs.evaluatorPolicies
            );
        } else if (phase == 3) {
            _phaseThree(
                inputs.room,
                inputs.teeIdentity,
                inputs.resultVerifier,
                inputs.composeHash,
                inputs.attestationVerifier,
                inputs.qvlReleasePolicyHash,
                inputs.evaluatorPolicies,
                inputs.evaluatorPolicySetRoot,
                inputs.governanceController
            );
        } else if (phase == 4) {
            _phaseFour(inputs);
        } else {
            revert("DILIGENCE_RELEASE_PHASE must be 1, 2, 3, or 4");
        }

        console.log("Diligence release phase:", phase);
        console.log("DiligenceRoom:", address(inputs.room));
        console.log("Approved compose hashes:", inputs.room.approvedComposeCount());
        console.log("Approved TEE identities:", inputs.room.approvedTeeIdentityCount());
        console.log("Pending compose hashes:", inputs.room.pendingComposeCount());
        console.log("Pending TEE identities:", inputs.room.pendingTeeIdentityCount());
        console.log("Attestation verifier:", inputs.room.attestationVerifier());
        console.logBytes32(inputs.room.attestationReleasePolicyHash());
        console.log("Attestation binding frozen:", inputs.room.attestationBindingFrozen());
        console.log("Approved evaluator policies:", inputs.room.approvedEvaluatorPolicyCount());
        console.logBytes32(inputs.room.evaluatorPolicySetRoot());
        console.log("Developer:", inputs.room.developer());
        console.log("Pending developer:", inputs.room.pendingDeveloper());
        console.log("Pending developer activates at:", inputs.room.pendingDeveloperActivatesAt());
    }

    function _requireCommonReleaseInputs(uint256 phase, ReleaseInputs memory inputs) internal view {
        DiligenceRoom room = inputs.room;
        require(
            inputs.roomRuntimeCodeHash != bytes32(0) && address(room).codehash == inputs.roomRuntimeCodeHash,
            "DiligenceRoom runtime code hash mismatch"
        );
        require(inputs.operator != address(0), "diligence operator must be nonzero");
        require(inputs.governanceController != address(0), "diligence governance controller must be nonzero");
        require(
            inputs.governanceController != inputs.operator && inputs.governanceController != address(room),
            "diligence governance controller conflicts with deployment authority"
        );
        require(room.initialDeveloper() == inputs.operator, "diligence initial developer mismatch");
        require(
            room.releaseGovernanceController() == inputs.governanceController,
            "DiligenceRoom release governance controller mismatch"
        );
        if (phase <= 3) {
            require(
                room.developer() == inputs.operator && room.pendingDeveloper() == address(0)
                    && room.pendingDeveloperActivatesAt() == 0,
                "operator does not own an unencumbered DiligenceRoom"
            );
        } else {
            require(
                phase == 4 && room.developer() == inputs.operator
                    && room.pendingDeveloper() == inputs.governanceController
                    && room.pendingDeveloperActivatesAt() != 0,
                "phase 4 requires the exact pending governance handoff"
            );
        }
        require(inputs.teeIdentity != address(0), "diligence TEE identity must be nonzero");
        require(inputs.resultVerifier != address(0), "diligence result verifier must be nonzero");
        require(inputs.composeHash != bytes32(0), "diligence compose hash must be nonzero");
        require(inputs.attestationVerifier != address(0), "diligence attestation verifier must be nonzero");
        require(inputs.qvlReleasePolicyHash != bytes32(0), "diligence QVL policy hash must be nonzero");
        require(inputs.evaluatorPolicySetRoot != bytes32(0), "diligence evaluator policy root must be nonzero");
        for (uint256 i = 0; i < 3; i++) {
            require(inputs.evaluatorPolicies[i] != bytes32(0), "diligence evaluator policy must be nonzero");
            for (uint256 j = i + 1; j < 3; j++) {
                require(
                    inputs.evaluatorPolicies[i] != inputs.evaluatorPolicies[j],
                    "diligence evaluator policies must be distinct"
                );
            }
        }
        require(
            room.computeEvaluatorPolicySetRoot(inputs.evaluatorPolicies) == inputs.evaluatorPolicySetRoot,
            "diligence evaluator policy root mismatch"
        );
        require(
            inputs.attestationVerifier != inputs.operator && inputs.attestationVerifier != inputs.resultVerifier
                && inputs.attestationVerifier != room.resultVerifier() && inputs.attestationVerifier != address(room)
                && inputs.attestationVerifier != inputs.teeIdentity
                && inputs.attestationVerifier != inputs.governanceController,
            "diligence attestation verifier conflicts with a release role"
        );
        require(
            inputs.teeIdentity != inputs.operator && inputs.teeIdentity != inputs.resultVerifier
                && inputs.teeIdentity != room.resultVerifier() && inputs.teeIdentity != address(room)
                && inputs.teeIdentity != inputs.attestationVerifier
                && inputs.teeIdentity != inputs.governanceController,
            "diligence TEE conflicts with a control role"
        );
        require(
            inputs.governanceController != inputs.resultVerifier && inputs.governanceController != room.resultVerifier()
                && inputs.governanceController != inputs.attestationVerifier,
            "diligence governance controller conflicts with a verifier role"
        );
        require(room.feeBpsFrozen() && room.feeBps() == room.DEFAULT_FEE_BPS(), "diligence fee is not release-frozen");
        require(room.computeSettlementPolicyEnabled(), "diligence compute policy is not enabled");
        require(
            room.composeApprovalRequired() && room.teeIdentityApprovalRequired() && room.approvalRequirementsFrozen(),
            "diligence approval requirements are not frozen on-chain"
        );
    }

    function _phaseOne(
        DiligenceRoom room,
        address resultVerifier,
        bytes32 composeHash,
        address attestationVerifier,
        bytes32 qvlReleasePolicyHash,
        bytes32[3] memory evaluatorPolicies
    ) internal {
        require(
            room.approvedComposeCount() == 0 && room.approvedTeeIdentityCount() == 0 && room.pendingComposeCount() == 0
                && room.pendingTeeIdentityCount() == 0 && !room.composeAdditionsFrozen()
                && !room.teeIdentityAdditionsFrozen() && room.attestationVerifier() == address(0)
                && room.attestationReleasePolicyHash() == bytes32(0) && room.pendingAttestationBindingActivatesAt() == 0
                && !room.attestationBindingFrozen() && room.resultVerifier() == address(0)
                && room.pendingResultVerifierActivatesAt() == 0 && !room.resultVerifierFrozen()
                && room.approvedEvaluatorPolicyCount() == 0 && room.pendingEvaluatorPolicyCount() == 0
                && !room.evaluatorPolicySetFrozen() && room.evaluatorPolicySetRoot() == bytes32(0),
            "phase 1 requires the exact fresh empty-admission room"
        );
        require(!room.approvedComposeHashes(composeHash), "compose hash is already approved");
        require(room.pendingComposeActivations(composeHash) == 0, "compose proposal already exists");

        vm.startBroadcast();
        room.proposeComposeAndEvaluatorPolicySet(composeHash, evaluatorPolicies);
        room.proposeResultVerifier(resultVerifier);
        room.proposeAttestationBinding(attestationVerifier, qvlReleasePolicyHash);
        vm.stopBroadcast();

        require(room.pendingComposeActivations(composeHash) > block.timestamp, "compose proposal was not staged");
        require(
            room.pendingAttestationVerifier() == attestationVerifier
                && room.pendingAttestationReleasePolicyHash() == qvlReleasePolicyHash
                && room.pendingAttestationBindingActivatesAt() > block.timestamp
                && room.pendingResultVerifier() == resultVerifier
                && room.pendingResultVerifierActivatesAt() > block.timestamp,
            "attestation binding was not staged"
        );
        require(
            room.pendingComposeCount() == 1 && room.approvedComposeCount() == 0 && room.pendingTeeIdentityCount() == 0
                && room.approvedTeeIdentityCount() == 0 && room.pendingEvaluatorPolicyCount() == 3
                && room.approvedEvaluatorPolicyCount() == 0,
            "phase 1 did not stage the exact compose admission"
        );
    }

    function _phaseTwo(
        DiligenceRoom room,
        address teeIdentity,
        address resultVerifier,
        bytes32 composeHash,
        address attestationVerifier,
        bytes32 qvlReleasePolicyHash,
        bytes32[3] memory evaluatorPolicies
    ) internal {
        require(
            room.approvedComposeCount() == 0 && room.approvedTeeIdentityCount() == 0 && room.pendingComposeCount() == 1
                && room.pendingTeeIdentityCount() == 0 && !room.composeAdditionsFrozen()
                && !room.teeIdentityAdditionsFrozen() && room.attestationVerifier() == address(0)
                && room.attestationReleasePolicyHash() == bytes32(0)
                && room.pendingAttestationVerifier() == attestationVerifier
                && room.pendingAttestationReleasePolicyHash() == qvlReleasePolicyHash
                && !room.attestationBindingFrozen() && room.resultVerifier() == address(0)
                && room.pendingResultVerifier() == resultVerifier && room.pendingEvaluatorPolicyCount() == 3
                && room.approvedEvaluatorPolicyCount() == 0 && !room.evaluatorPolicySetFrozen(),
            "phase 2 requires the exact phase-1 admission state"
        );
        uint256 composeActivatesAt = room.pendingComposeActivations(composeHash);
        require(composeActivatesAt != 0 && composeActivatesAt <= block.timestamp, "compose timelock has not elapsed");
        uint256 attestationActivatesAt = room.pendingAttestationBindingActivatesAt();
        require(
            attestationActivatesAt != 0 && attestationActivatesAt <= block.timestamp,
            "attestation timelock has not elapsed"
        );
        require(room.pendingTeeIdentityActivations(teeIdentity) == 0, "TEE proposal already exists");
        require(room.teeIdentityComposeHash(teeIdentity) == bytes32(0), "TEE identity is already admitted");

        vm.startBroadcast();
        room.activateComposeAndEvaluatorPolicySet(composeHash, evaluatorPolicies);
        room.activateResultVerifier();
        room.freezeResultVerifier();
        room.activateAttestationBinding();
        room.freezeAttestationBinding();
        room.proposeTeeIdentity(teeIdentity, composeHash);
        vm.stopBroadcast();

        require(
            room.approvedComposeCount() == 1 && room.approvedComposeHashes(composeHash)
                && room.pendingComposeCount() == 0 && room.approvedTeeIdentityCount() == 0
                && room.pendingTeeIdentityCount() == 1 && room.pendingTeeIdentityComposeHash(teeIdentity) == composeHash
                && room.pendingTeeIdentityActivations(teeIdentity) > block.timestamp
                && room.attestationVerifier() == attestationVerifier
                && room.attestationReleasePolicyHash() == qvlReleasePolicyHash && room.attestationBindingFrozen()
                && room.pendingAttestationBindingActivatesAt() == 0 && room.resultVerifier() == resultVerifier
                && room.resultVerifierFrozen() && room.pendingResultVerifier() == address(0)
                && room.pendingEvaluatorPolicyCount() == 0 && room.approvedEvaluatorPolicyCount() == 3
                && !room.evaluatorPolicySetFrozen(),
            "phase 2 did not stage the exact TEE binding"
        );
    }

    function _phaseThree(
        DiligenceRoom room,
        address teeIdentity,
        address resultVerifier,
        bytes32 composeHash,
        address attestationVerifier,
        bytes32 qvlReleasePolicyHash,
        bytes32[3] memory evaluatorPolicies,
        bytes32 evaluatorPolicySetRoot,
        address governanceController
    ) internal {
        bytes32[3] memory activeEvaluatorPolicies = room.evaluatorPolicies();
        require(
            room.approvedComposeCount() == 1 && room.approvedComposeHashes(composeHash)
                && room.pendingComposeCount() == 0 && room.approvedTeeIdentityCount() == 0
                && room.pendingTeeIdentityCount() == 1 && !room.composeAdditionsFrozen()
                && !room.teeIdentityAdditionsFrozen() && room.attestationVerifier() == attestationVerifier
                && room.attestationReleasePolicyHash() == qvlReleasePolicyHash && room.attestationBindingFrozen()
                && room.pendingAttestationVerifier() == address(0)
                && room.pendingAttestationReleasePolicyHash() == bytes32(0)
                && room.pendingAttestationBindingActivatesAt() == 0 && room.pendingEvaluatorPolicyCount() == 0
                && room.approvedEvaluatorPolicyCount() == 3 && !room.evaluatorPolicySetFrozen()
                && room.resultVerifier() == resultVerifier && room.resultVerifierFrozen()
                && room.pendingResultVerifier() == address(0) && room.pendingResultVerifierActivatesAt() == 0
                && room.approvedEvaluatorPolicies(evaluatorPolicies[0])
                && room.approvedEvaluatorPolicies(evaluatorPolicies[1])
                && room.approvedEvaluatorPolicies(evaluatorPolicies[2])
                && room.pendingEvaluatorPolicyActivations(evaluatorPolicies[0]) == 0
                && room.pendingEvaluatorPolicyActivations(evaluatorPolicies[1]) == 0
                && room.pendingEvaluatorPolicyActivations(evaluatorPolicies[2]) == 0
                && room.computeEvaluatorPolicySetRoot(activeEvaluatorPolicies) == evaluatorPolicySetRoot
                && room.computeEvaluatorPolicySetRoot(evaluatorPolicies) == evaluatorPolicySetRoot,
            "phase 3 requires the exact phase-2 admission state"
        );
        uint256 teeActivatesAt = room.pendingTeeIdentityActivations(teeIdentity);
        require(teeActivatesAt != 0 && teeActivatesAt <= block.timestamp, "TEE timelock has not elapsed");
        require(room.pendingTeeIdentityComposeHash(teeIdentity) == composeHash, "pending TEE binding mismatch");

        vm.startBroadcast();
        room.activateTeeIdentity(teeIdentity);
        room.freezeComposeAndEvaluatorPolicySets();
        room.freezeTeeIdentityAdditions();
        room.proposeDeveloper(governanceController);
        vm.stopBroadcast();

        require(
            room.approvedComposeCount() == 1 && room.approvedTeeIdentityCount() == 1 && room.pendingComposeCount() == 0
                && room.pendingTeeIdentityCount() == 0 && room.composeAdditionsFrozen()
                && room.teeIdentityAdditionsFrozen() && room.approvedComposeHashes(composeHash)
                && room.teeIdentityComposeHash(teeIdentity) == composeHash && room.resultVerifier() == resultVerifier
                && room.resultVerifierFrozen() && room.attestationVerifier() == attestationVerifier
                && room.attestationReleasePolicyHash() == qvlReleasePolicyHash && room.attestationBindingFrozen()
                && room.evaluatorPolicySetFrozen() && room.approvedEvaluatorPolicyCount() == 3
                && room.pendingEvaluatorPolicyCount() == 0 && room.evaluatorPolicySetRoot() == evaluatorPolicySetRoot
                && room.approvedEvaluatorPolicies(evaluatorPolicies[0])
                && room.approvedEvaluatorPolicies(evaluatorPolicies[1])
                && room.approvedEvaluatorPolicies(evaluatorPolicies[2]) && room.developer() != governanceController
                && room.pendingDeveloper() == governanceController
                && room.pendingDeveloperActivatesAt() > block.timestamp,
            "phase 3 did not close the release policy and stage governance"
        );
    }

    function _phaseFour(ReleaseInputs memory inputs) internal {
        DiligenceRoom room = inputs.room;
        _requireClosedReleaseState(inputs);
        uint256 activatesAt = room.pendingDeveloperActivatesAt();
        require(activatesAt <= block.timestamp, "developer-transfer timelock has not elapsed");

        _acceptDeveloper(room);

        require(
            room.developer() == inputs.governanceController && room.pendingDeveloper() == address(0)
                && room.pendingDeveloperActivatesAt() == 0,
            "phase 4 did not accept the exact governance controller"
        );
        _requireClosedReleaseState(inputs);
    }

    function _acceptDeveloper(DiligenceRoom room) internal virtual {
        vm.startBroadcast();
        room.acceptDeveloper();
        vm.stopBroadcast();
    }

    function _requireClosedReleaseState(ReleaseInputs memory inputs) internal view {
        DiligenceRoom room = inputs.room;
        require(
            room.approvedComposeCount() == 1 && room.approvedTeeIdentityCount() == 1 && room.pendingComposeCount() == 0
                && room.pendingTeeIdentityCount() == 0 && room.composeAdditionsFrozen()
                && room.teeIdentityAdditionsFrozen() && room.approvedComposeHashes(inputs.composeHash)
                && room.teeIdentityComposeHash(inputs.teeIdentity) == inputs.composeHash
                && room.resultVerifier() == inputs.resultVerifier && room.resultVerifierFrozen()
                && room.attestationVerifier() == inputs.attestationVerifier
                && room.attestationReleasePolicyHash() == inputs.qvlReleasePolicyHash && room.attestationBindingFrozen()
                && room.evaluatorPolicySetFrozen() && room.approvedEvaluatorPolicyCount() == 3
                && room.pendingEvaluatorPolicyCount() == 0
                && room.evaluatorPolicySetRoot() == inputs.evaluatorPolicySetRoot
                && room.approvedEvaluatorPolicies(inputs.evaluatorPolicies[0])
                && room.approvedEvaluatorPolicies(inputs.evaluatorPolicies[1])
                && room.approvedEvaluatorPolicies(inputs.evaluatorPolicies[2]),
            "phase 4 requires the exact closed diligence release policy"
        );
    }
}
