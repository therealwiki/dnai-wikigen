// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Test} from "forge-std/Test.sol";

import {DiligenceRoom} from "../src/DiligenceRoom.sol";

contract DiligenceAdmissionHandler is Test {
    DiligenceRoom public immutable room;

    bytes32[4] internal _composeHashes;
    address[4] internal _teeIdentities;

    constructor() {
        room = new DiligenceRoom(true, address(0xBEEF));
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();

        for (uint256 i = 0; i < 4; i++) {
            _composeHashes[i] = keccak256(abi.encodePacked("diligence-compose", i));
            _teeIdentities[i] = address(uint160(uint256(keccak256(abi.encodePacked("diligence-tee", i)))));
        }
    }

    function composeHash(uint256 index) public view returns (bytes32) {
        return _composeHashes[index % _composeHashes.length];
    }

    function teeIdentity(uint256 index) public view returns (address) {
        return _teeIdentities[index % _teeIdentities.length];
    }

    function proposeCompose(uint256 index) external {
        try room.proposeComposeHash(composeHash(index)) {} catch {}
    }

    function activateCompose(uint256 index, bool elapseTimelock) external {
        bytes32 candidate = composeHash(index);
        uint256 activatesAt = room.pendingComposeActivations(candidate);
        if (elapseTimelock && activatesAt != 0) vm.warp(activatesAt);
        try room.activateComposeHash(candidate) {} catch {}
    }

    function cancelCompose(uint256 index) external {
        try room.cancelComposeHashProposal(composeHash(index)) {} catch {}
    }

    function revokeCompose(uint256 index) external {
        try room.revokeComposeHash(composeHash(index)) {} catch {}
    }

    function proposeTee(uint256 teeIndex, uint256 composeIndex) external {
        try room.proposeTeeIdentity(teeIdentity(teeIndex), composeHash(composeIndex)) {} catch {}
    }

    function activateTee(uint256 index, bool elapseTimelock) external {
        address candidate = teeIdentity(index);
        uint256 activatesAt = room.pendingTeeIdentityActivations(candidate);
        if (elapseTimelock && activatesAt != 0) vm.warp(activatesAt);
        try room.activateTeeIdentity(candidate) {} catch {}
    }

    function cancelTee(uint256 index) external {
        try room.cancelTeeIdentityProposal(teeIdentity(index)) {} catch {}
    }

    function revokeTee(uint256 index) external {
        try room.revokeTeeIdentity(teeIdentity(index)) {} catch {}
    }

    function freezeComposeAdditions() external {
        try room.freezeComposeAdditions() {} catch {}
    }

    function freezeTeeAdditions() external {
        try room.freezeTeeIdentityAdditions() {} catch {}
    }
}

contract DiligenceRoomAdmissionInvariantTest is StdInvariant, Test {
    DiligenceAdmissionHandler internal handler;
    DiligenceRoom internal room;

    function setUp() public {
        handler = new DiligenceAdmissionHandler();
        room = handler.room();
        targetContract(address(handler));
    }

    function invariant_AdmissionCountersExactlyMatchEnumerableModel() public view {
        uint256 activeCompose;
        uint256 pendingCompose;
        uint256 activeTee;
        uint256 pendingTee;

        for (uint256 i = 0; i < 4; i++) {
            bytes32 compose = handler.composeHash(i);
            address tee = handler.teeIdentity(i);
            if (room.approvedComposeHashes(compose)) activeCompose += 1;
            if (room.pendingComposeActivations(compose) != 0) pendingCompose += 1;
            if (room.teeIdentityComposeHash(tee) != bytes32(0)) activeTee += 1;
            if (room.pendingTeeIdentityActivations(tee) != 0) pendingTee += 1;
        }

        assertEq(room.approvedComposeCount(), activeCompose);
        assertEq(room.pendingComposeCount(), pendingCompose);
        assertEq(room.approvedTeeIdentityCount(), activeTee);
        assertEq(room.pendingTeeIdentityCount(), pendingTee);
    }

    function invariant_TeeBindingsAreExactAndNeverZeroValuedAdmissions() public view {
        for (uint256 i = 0; i < 4; i++) {
            address tee = handler.teeIdentity(i);
            bytes32 activeBinding = room.teeIdentityComposeHash(tee);
            bytes32 pendingBinding = room.pendingTeeIdentityComposeHash(tee);
            uint256 activatesAt = room.pendingTeeIdentityActivations(tee);

            if (activeBinding != bytes32(0)) {
                assertEq(activatesAt, 0);
                assertEq(pendingBinding, bytes32(0));
            }
            if (activatesAt != 0) assertNotEq(pendingBinding, bytes32(0));
            if (pendingBinding != bytes32(0)) assertNotEq(activatesAt, 0);
        }
    }

    function invariant_FrozenAdmissionSetsHaveNoPendingExpansion() public view {
        if (room.composeAdditionsFrozen()) assertEq(room.pendingComposeCount(), 0);
        if (room.teeIdentityAdditionsFrozen()) assertEq(room.pendingTeeIdentityCount(), 0);
    }

    function invariant_MandatoryApprovalRequirementsStayEnabledAndFrozen() public view {
        assertTrue(room.composeApprovalRequired());
        assertTrue(room.teeIdentityApprovalRequired());
        assertTrue(room.approvalRequirementsFrozen());
    }
}
