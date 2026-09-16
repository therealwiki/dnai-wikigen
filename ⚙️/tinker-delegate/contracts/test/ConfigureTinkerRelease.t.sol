// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ConfigureTinkerReleaseScript} from "../script/ConfigureTinkerRelease.s.sol";
import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

contract ConfigureTinkerReleaseHarness is ConfigureTinkerReleaseScript {
    function executeConfiguredPhase(uint256 phase, ReleaseInputs memory inputs) external {
        _executePhase(phase, inputs);
    }
}

contract ConfigureTinkerReleaseTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 internal constant POLICY_UNIT = 1e18;

    ConfigureTinkerReleaseHarness internal script;
    TinkerAccountEncumbrance internal encumbrance;
    address internal operator;
    address internal manager = makeAddr("tinker-release-manager");
    bytes32 internal accountCommitment = keccak256("tinker-release-account");
    bytes32 internal composeHash = keccak256("tinker-release-compose");
    // These are unitless policy units, not ETH-denominated balances.
    uint256 internal maxAddBalanceWei = 2 * POLICY_UNIT;
    uint256 internal maxSpendWei = POLICY_UNIT / 2;

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        encumbrance =
            new TinkerAccountEncumbrance(operator, accountCommitment, bytes32(0), maxAddBalanceWei, maxSpendWei);
        script = new ConfigureTinkerReleaseHarness();
    }

    function test_TwoTimelockedPhasesProduceExactFrozenRelease() public {
        bytes32[] memory composeSet = _composeSet();
        address[] memory managerSet = _managerSet(manager);
        bytes32 composeRoot = encumbrance.computeComposeRoot(composeSet);
        bytes32 managerRoot = encumbrance.computeManagerRoot(managerSet);
        bytes32 expectedCommitment = encumbrance.computeReleasePolicyCommitment(
            accountCommitment,
            maxAddBalanceWei,
            maxSpendWei,
            composeRoot,
            composeSet.length,
            managerRoot,
            managerSet.length
        );

        _runPhase(1, manager);
        assertTrue(encumbrance.emergencyHalted());
        assertFalse(encumbrance.releasePolicyFrozen());
        assertEq(encumbrance.pendingReleasePolicyCommitment(), expectedCommitment);
        assertEq(encumbrance.pendingComposeRoot(), composeRoot);
        assertEq(encumbrance.pendingManagerRoot(), managerRoot);
        assertEq(encumbrance.pendingComposeCount(), 1);
        assertEq(encumbrance.pendingManagerCount(), 1);
        assertGt(encumbrance.pendingReleasePolicyActivatesAt(), block.timestamp);

        vm.warp(encumbrance.pendingReleasePolicyActivatesAt());
        _runPhase(2, manager);
        assertTrue(encumbrance.releasePolicyFrozen());
        assertFalse(encumbrance.emergencyHalted());
        assertEq(encumbrance.releasePolicyCommitment(), expectedCommitment);
        assertEq(encumbrance.approvedComposeRoot(), composeRoot);
        assertEq(encumbrance.releaseComposeRoot(), composeRoot);
        assertEq(encumbrance.managerRoot(), managerRoot);
        assertEq(encumbrance.releaseManagerRoot(), managerRoot);
        assertEq(encumbrance.approvedComposeCount(), 1);
        assertEq(encumbrance.managerCount(), 1);
        assertEq(encumbrance.pendingComposeCount(), 0);
        assertEq(encumbrance.pendingManagerCount(), 0);
        assertEq(encumbrance.pendingReleasePolicyCommitment(), bytes32(0));
        assertEq(encumbrance.pendingReleasePolicyActivatesAt(), 0);
    }

    function test_ExplicitZeroManagerProducesExactEmptyManagerRelease() public {
        _runPhase(1, address(0));
        assertEq(encumbrance.pendingManagerCount(), 0);
        bytes32 emptyManagerRoot = encumbrance.computeManagerRoot(new address[](0));
        assertEq(encumbrance.pendingManagerRoot(), emptyManagerRoot);

        vm.warp(encumbrance.pendingReleasePolicyActivatesAt());
        _runPhase(2, address(0));
        assertEq(encumbrance.managerCount(), 0);
        assertEq(encumbrance.releaseManagerCount(), 0);
        assertEq(encumbrance.managerRoot(), emptyManagerRoot);
        assertEq(encumbrance.releaseManagerRoot(), emptyManagerRoot);
    }

    function test_CannotSkipTimelockReplayOrUseUnknownPhase() public {
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 release proposal"));
        _runPhase(2, manager);

        _runPhase(1, manager);
        vm.expectRevert(bytes("phase 1 requires no existing or pending release"));
        _runPhase(1, manager);
        vm.expectRevert(bytes("Tinker release timelock has not elapsed"));
        _runPhase(2, manager);

        vm.expectRevert(bytes("TINKER_ENCUMBRANCE_RELEASE_PHASE must be 1 or 2"));
        _runPhase(3, manager);
    }

    function test_PhaseOneRequiresExactFreshDraft() public {
        TinkerAccountEncumbrance differentDraft = new TinkerAccountEncumbrance(
            operator, accountCommitment, keccak256("different-compose"), maxAddBalanceWei, maxSpendWei
        );
        ConfigureTinkerReleaseScript.ReleaseInputs memory inputs = _inputs(manager);
        inputs.encumbrance = differentDraft;
        inputs.encumbranceRuntimeCodeHash = address(differentDraft).codehash;
        vm.expectRevert(bytes("phase 1 requires the exact fresh halted draft"));
        script.executeConfiguredPhase(1, inputs);
    }

    function test_PhaseTwoRequiresExactReviewedProposal() public {
        _runPhase(1, manager);
        vm.warp(encumbrance.pendingReleasePolicyActivatesAt());

        ConfigureTinkerReleaseScript.ReleaseInputs memory inputs = _inputs(manager);
        inputs.maxSpendWei += 1;
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 release proposal"));
        script.executeConfiguredPhase(2, inputs);
    }

    function test_RuntimeHashOwnerAndChainMustMatch() public {
        ConfigureTinkerReleaseScript.ReleaseInputs memory inputs = _inputs(manager);
        inputs.encumbranceRuntimeCodeHash = keccak256("wrong-runtime");
        vm.expectRevert(bytes("TinkerAccountEncumbrance runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs(manager);
        inputs.operator = makeAddr("wrong-operator");
        vm.expectRevert(bytes("operator does not own TinkerAccountEncumbrance"));
        script.executeConfiguredPhase(1, inputs);

        vm.chainId(1);
        vm.expectRevert(bytes("tinker release is Base Sepolia only"));
        script.executeConfiguredPhase(1, _inputs(manager));
    }

    function test_ControlRoleCollisionsAndPendingOwnershipBlockRelease() public {
        ConfigureTinkerReleaseScript.ReleaseInputs memory inputs = _inputs(operator);
        vm.expectRevert(bytes("Tinker manager conflicts with a control role"));
        script.executeConfiguredPhase(1, inputs);

        vm.prank(operator);
        encumbrance.transferOwnership(makeAddr("pending-governance"));
        vm.expectRevert(bytes("pending ownership transfer blocks release"));
        _runPhase(1, manager);
    }

    function test_CommonInputsMustBeNonzeroAndContractMustRemainHalted() public {
        ConfigureTinkerReleaseScript.ReleaseInputs memory inputs = _inputs(manager);
        inputs.accountCommitment = bytes32(0);
        vm.expectRevert(bytes("release account commitment must be nonzero"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs(manager);
        inputs.composeHash = bytes32(0);
        vm.expectRevert(bytes("release compose hash must be nonzero"));
        script.executeConfiguredPhase(1, inputs);

        _runPhase(1, manager);
        vm.warp(encumbrance.pendingReleasePolicyActivatesAt());
        _runPhase(2, manager);
        vm.expectRevert(bytes("TinkerAccountEncumbrance must remain halted until phase 2"));
        script.executeConfiguredPhase(2, _inputs(manager));
    }

    function test_CommonInputsRejectInvalidPolicyUnitLimitsBeforeReleaseChecks() public {
        ConfigureTinkerReleaseScript.ReleaseInputs memory inputs = _inputs(manager);
        inputs.maxAddBalanceWei = 0;
        vm.expectRevert(bytes("Tinker per-operation policy-unit caps must be nonzero"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs(manager);
        inputs.maxSpendWei = inputs.maxAddBalanceWei + 1;
        vm.expectRevert(bytes("Tinker spend policy-unit cap exceeds add-balance cap"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs(manager);
        inputs.maxAddBalanceWei = encumbrance.MAX_POLICY_UNITS_PER_OPERATION() + 1;
        vm.expectRevert(bytes("Tinker per-operation policy-unit cap exceeds hard maximum"));
        script.executeConfiguredPhase(1, inputs);
    }

    function _runPhase(uint256 phase, address releaseManager) internal {
        script.executeConfiguredPhase(phase, _inputs(releaseManager));
    }

    function _inputs(address releaseManager) internal view returns (ConfigureTinkerReleaseScript.ReleaseInputs memory) {
        return ConfigureTinkerReleaseScript.ReleaseInputs({
            encumbrance: encumbrance,
            encumbranceRuntimeCodeHash: address(encumbrance).codehash,
            operator: operator,
            accountCommitment: accountCommitment,
            maxAddBalanceWei: maxAddBalanceWei,
            maxSpendWei: maxSpendWei,
            composeHash: composeHash,
            manager: releaseManager
        });
    }

    function _composeSet() internal view returns (bytes32[] memory values) {
        values = new bytes32[](1);
        values[0] = composeHash;
    }

    function _managerSet(address releaseManager) internal pure returns (address[] memory values) {
        values = new address[](releaseManager == address(0) ? 0 : 1);
        if (releaseManager != address(0)) values[0] = releaseManager;
    }
}
