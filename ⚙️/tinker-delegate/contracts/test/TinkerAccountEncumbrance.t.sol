// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

contract TinkerAccountEncumbranceTest is Test {
    uint256 internal constant POLICY_UNIT = 1e18;

    TinkerAccountEncumbrance internal encumbrance;

    address internal owner = makeAddr("owner");
    address internal manager = makeAddr("manager");
    address internal requester = makeAddr("requester");
    address internal nextOwner = makeAddr("next-owner");
    address internal stranger = makeAddr("stranger");

    bytes32 internal accountCommitment = keccak256("tinker-account-draft");
    bytes32 internal releaseAccountCommitment = keccak256("tinker-account-release");
    bytes32 internal composeHash = keccak256("compose-v1");
    bytes32 internal operationId = keccak256("operation-1");
    bytes32 internal receiptHash = keccak256("bounded-receipt");

    // These are unitless policy units, not ETH-denominated balances.
    uint256 internal maxAddBalanceWei = 10 * POLICY_UNIT;
    uint256 internal maxSpendWei = 2 * POLICY_UNIT;

    function setUp() public {
        encumbrance = new TinkerAccountEncumbrance(owner, accountCommitment, bytes32(0), maxAddBalanceWei, maxSpendWei);
    }

    function _composeSet() internal view returns (bytes32[] memory values) {
        values = new bytes32[](1);
        values[0] = composeHash;
    }

    function _managerSet() internal view returns (address[] memory values) {
        values = new address[](1);
        values[0] = manager;
    }

    function _emptyManagerSet() internal pure returns (address[] memory values) {
        values = new address[](0);
    }

    function _propose(address[] memory policyManagers) internal {
        vm.prank(owner);
        encumbrance.proposeReleasePolicy(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, _composeSet(), policyManagers
        );
    }

    function _activate(address[] memory policyManagers) internal {
        _propose(policyManagers);
        vm.warp(block.timestamp + encumbrance.RELEASE_POLICY_DELAY());
        vm.prank(owner);
        encumbrance.activateAndFreezeReleasePolicy();
    }

    function test_InitialDraftIsHaltedWithEmptyAuthoritySets() public view {
        bytes32[] memory emptyComposeSet = new bytes32[](0);
        address[] memory emptyManagers = _emptyManagerSet();

        assertEq(encumbrance.owner(), owner);
        assertEq(encumbrance.pendingOwner(), address(0));
        assertEq(encumbrance.accountCommitment(), accountCommitment);
        assertEq(encumbrance.maxAddBalanceWei(), maxAddBalanceWei);
        assertEq(encumbrance.maxSpendWei(), maxSpendWei);
        assertFalse(encumbrance.approvedComposeHashes(composeHash));
        assertEq(encumbrance.approvedComposeCount(), 0);
        assertEq(encumbrance.approvedComposeRoot(), encumbrance.computeComposeRoot(emptyComposeSet));
        assertEq(encumbrance.managerCount(), 0);
        assertEq(encumbrance.managerRoot(), encumbrance.computeManagerRoot(emptyManagers));
        assertTrue(encumbrance.emergencyHalted());
        assertFalse(encumbrance.releasePolicyFrozen());
        assertEq(encumbrance.releasePolicyCommitment(), bytes32(0));
        assertEq(encumbrance.pendingReleasePolicyActivatesAt(), 0);
        assertEq(encumbrance.pendingComposeCount(), 0);
        assertEq(encumbrance.pendingManagerCount(), 0);
    }

    function test_ConstructorRejectsZeroAndSelfOwnerAndZeroCommitments() public {
        vm.expectRevert(TinkerAccountEncumbrance.ZeroAddress.selector);
        new TinkerAccountEncumbrance(address(0), accountCommitment, composeHash, 1, 1);

        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(TinkerAccountEncumbrance.SelfAddress.selector);
        new TinkerAccountEncumbrance(predicted, accountCommitment, composeHash, 1, 1);

        vm.expectRevert(TinkerAccountEncumbrance.ZeroHash.selector);
        new TinkerAccountEncumbrance(owner, bytes32(0), composeHash, 1, 1);

        TinkerAccountEncumbrance emptyAuthorityDraft =
            new TinkerAccountEncumbrance(owner, accountCommitment, bytes32(0), 1, 1);
        assertEq(emptyAuthorityDraft.approvedComposeCount(), 0);
        assertEq(emptyAuthorityDraft.managerCount(), 0);
    }

    function test_FundingPolicyLimitsAreNonzeroOrderedAndHardCappedPolicyUnits() public {
        uint256 hardMaximum = encumbrance.MAX_POLICY_UNITS_PER_OPERATION();
        assertEq(hardMaximum, 10 * POLICY_UNIT);

        TinkerAccountEncumbrance exactMaximum =
            new TinkerAccountEncumbrance(owner, accountCommitment, composeHash, hardMaximum, hardMaximum);
        assertEq(exactMaximum.maxAddBalanceWei(), hardMaximum);
        assertEq(exactMaximum.maxSpendWei(), hardMaximum);

        vm.expectRevert(TinkerAccountEncumbrance.ZeroFundingPolicyLimit.selector);
        new TinkerAccountEncumbrance(owner, accountCommitment, composeHash, 0, 1);
        vm.expectRevert(TinkerAccountEncumbrance.ZeroFundingPolicyLimit.selector);
        new TinkerAccountEncumbrance(owner, accountCommitment, composeHash, 1, 0);
        vm.expectRevert(TinkerAccountEncumbrance.SpendLimitExceedsAddBalanceLimit.selector);
        new TinkerAccountEncumbrance(owner, accountCommitment, composeHash, 1, 2);
        vm.expectRevert(TinkerAccountEncumbrance.FundingPolicyLimitExceedsMaximum.selector);
        new TinkerAccountEncumbrance(owner, accountCommitment, composeHash, hardMaximum + 1, hardMaximum);
    }

    function test_DraftCannotAuthorizeOperations() public {
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.ReleasePolicyNotFrozen.selector);
        encumbrance.authorizeOperation(
            operationId, TinkerAccountEncumbrance.OperationKind.AddBalance, requester, composeHash, POLICY_UNIT
        );

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.ReleasePolicyNotFrozen.selector);
        encumbrance.settleOperation(operationId, false, receiptHash);
    }

    function test_ReleaseProposalRejectsInvalidPolicyUnitLimits() public {
        bytes32[] memory composeSet = _composeSet();
        address[] memory managers = _managerSet();
        uint256 overHardMaximum = encumbrance.MAX_POLICY_UNITS_PER_OPERATION() + 1;

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.ZeroFundingPolicyLimit.selector);
        encumbrance.proposeReleasePolicy(releaseAccountCommitment, 0, maxSpendWei, composeSet, managers);

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.SpendLimitExceedsAddBalanceLimit.selector);
        encumbrance.proposeReleasePolicy(releaseAccountCommitment, 1, 2, composeSet, managers);

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.FundingPolicyLimitExceedsMaximum.selector);
        encumbrance.proposeReleasePolicy(releaseAccountCommitment, overHardMaximum, maxSpendWei, composeSet, managers);
    }

    function test_ReleaseProposalExposesExactCommitmentAndCannotActivateEarly() public {
        bytes32[] memory composeSet = _composeSet();
        address[] memory managers = _managerSet();
        bytes32 composeRoot = encumbrance.computeComposeRoot(composeSet);
        bytes32 managerRoot = encumbrance.computeManagerRoot(managers);
        bytes32 expectedCommitment = encumbrance.computeReleasePolicyCommitment(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, composeRoot, 1, managerRoot, 1
        );

        _propose(managers);

        assertEq(encumbrance.pendingAccountCommitment(), releaseAccountCommitment);
        assertEq(encumbrance.pendingMaxAddBalanceWei(), maxAddBalanceWei);
        assertEq(encumbrance.pendingMaxSpendWei(), maxSpendWei);
        assertEq(encumbrance.pendingComposeRoot(), composeRoot);
        assertEq(encumbrance.pendingManagerRoot(), managerRoot);
        assertEq(encumbrance.pendingReleasePolicyCommitment(), expectedCommitment);
        assertEq(encumbrance.pendingComposeCount(), 1);
        assertEq(encumbrance.pendingComposeHashAt(0), composeHash);
        assertTrue(encumbrance.pendingComposeApprovals(composeHash));
        assertEq(encumbrance.pendingManagerCount(), 1);
        assertEq(encumbrance.pendingManagerAt(0), manager);
        assertTrue(encumbrance.pendingManagerApprovals(manager));

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.ReleasePolicyProposalExists.selector);
        encumbrance.proposeReleasePolicy(releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, composeSet, managers);

        uint64 activatesAt = encumbrance.pendingReleasePolicyActivatesAt();
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(TinkerAccountEncumbrance.ReleasePolicyActivationTooEarly.selector, activatesAt)
        );
        encumbrance.activateAndFreezeReleasePolicy();
    }

    function test_CancelReleaseProposalClearsEveryPendingEntry() public {
        _propose(_managerSet());

        vm.prank(owner);
        encumbrance.cancelReleasePolicyProposal();

        assertEq(encumbrance.pendingAccountCommitment(), bytes32(0));
        assertEq(encumbrance.pendingComposeRoot(), bytes32(0));
        assertEq(encumbrance.pendingManagerRoot(), bytes32(0));
        assertEq(encumbrance.pendingReleasePolicyCommitment(), bytes32(0));
        assertEq(encumbrance.pendingReleasePolicyActivatesAt(), 0);
        assertEq(encumbrance.pendingComposeCount(), 0);
        assertEq(encumbrance.pendingManagerCount(), 0);
        assertFalse(encumbrance.pendingComposeApprovals(composeHash));
        assertFalse(encumbrance.pendingManagerApprovals(manager));
        assertTrue(encumbrance.emergencyHalted());
    }

    function test_ActivationAtomicallyBindsExactPolicyClearsPendingAndUnhalts() public {
        bytes32[] memory composeSet = _composeSet();
        address[] memory managers = _managerSet();
        bytes32 composeRoot = encumbrance.computeComposeRoot(composeSet);
        bytes32 managersRoot = encumbrance.computeManagerRoot(managers);
        bytes32 expectedCommitment = encumbrance.computeReleasePolicyCommitment(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, composeRoot, 1, managersRoot, 1
        );

        _activate(managers);

        assertTrue(encumbrance.releasePolicyFrozen());
        assertFalse(encumbrance.emergencyHalted());
        assertEq(encumbrance.releasePolicyCommitment(), expectedCommitment);
        assertEq(encumbrance.accountCommitment(), releaseAccountCommitment);
        assertEq(encumbrance.maxAddBalanceWei(), maxAddBalanceWei);
        assertEq(encumbrance.maxSpendWei(), maxSpendWei);
        assertEq(encumbrance.releaseMaxAddBalanceWei(), maxAddBalanceWei);
        assertEq(encumbrance.releaseMaxSpendWei(), maxSpendWei);
        assertEq(encumbrance.approvedComposeCount(), 1);
        assertEq(encumbrance.approvedComposeRoot(), composeRoot);
        assertEq(encumbrance.releaseComposeCount(), 1);
        assertEq(encumbrance.releaseComposeRoot(), composeRoot);
        assertEq(encumbrance.managerCount(), 1);
        assertEq(encumbrance.managerRoot(), managersRoot);
        assertEq(encumbrance.releaseManagerCount(), 1);
        assertEq(encumbrance.releaseManagerRoot(), managersRoot);
        assertTrue(encumbrance.managers(manager));
        assertEq(encumbrance.pendingReleasePolicyActivatesAt(), 0);
        assertEq(encumbrance.pendingReleasePolicyCommitment(), bytes32(0));
        assertEq(encumbrance.pendingComposeCount(), 0);
        assertEq(encumbrance.pendingManagerCount(), 0);
        assertFalse(encumbrance.pendingComposeApprovals(composeHash));
        assertFalse(encumbrance.pendingManagerApprovals(manager));
    }

    function test_ReleaseSetsMustBeBoundedCanonicalAndRoleSeparated() public {
        bytes32[] memory composeSet = new bytes32[](2);
        composeSet[0] = bytes32(uint256(2));
        composeSet[1] = bytes32(uint256(1));
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.InvalidComposeSet.selector);
        encumbrance.proposeReleasePolicy(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, composeSet, _emptyManagerSet()
        );

        composeSet[0] = bytes32(uint256(1));
        composeSet[1] = bytes32(uint256(1));
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.InvalidComposeSet.selector);
        encumbrance.proposeReleasePolicy(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, composeSet, _emptyManagerSet()
        );

        bytes32[] memory tooManyComposes = new bytes32[](encumbrance.MAX_RELEASE_COMPOSES() + 1);
        for (uint256 i = 0; i < tooManyComposes.length; i++) {
            tooManyComposes[i] = bytes32(i + 1);
        }
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.TooManyComposeHashes.selector);
        encumbrance.proposeReleasePolicy(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, tooManyComposes, _emptyManagerSet()
        );

        address[3] memory conflictedManagers = [owner, address(encumbrance), address(0)];
        for (uint256 i = 0; i < conflictedManagers.length; i++) {
            address conflicted = conflictedManagers[i];
            address[] memory managers = new address[](1);
            managers[0] = conflicted;
            vm.prank(owner);
            if (conflicted == address(0)) vm.expectRevert(TinkerAccountEncumbrance.InvalidManagerSet.selector);
            else vm.expectRevert(TinkerAccountEncumbrance.RoleConflict.selector);
            encumbrance.proposeReleasePolicy(
                releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, _composeSet(), managers
            );
        }
    }

    function test_OwnershipIsExactTwoStepAndCannotCollideWithContractOrManagers() public {
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.SelfAddress.selector);
        encumbrance.transferOwnership(address(encumbrance));

        _propose(_managerSet());
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.RoleConflict.selector);
        encumbrance.transferOwnership(manager);

        vm.prank(owner);
        encumbrance.transferOwnership(nextOwner);
        assertEq(encumbrance.owner(), owner);
        assertEq(encumbrance.pendingOwner(), nextOwner);

        vm.prank(stranger);
        vm.expectRevert(TinkerAccountEncumbrance.NotPendingOwner.selector);
        encumbrance.acceptOwnership();
        assertEq(encumbrance.owner(), owner);
        assertEq(encumbrance.pendingOwner(), nextOwner);

        vm.prank(nextOwner);
        encumbrance.acceptOwnership();
        assertEq(encumbrance.owner(), nextOwner);
        assertEq(encumbrance.pendingOwner(), address(0));

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.cancelReleasePolicyProposal();
    }

    function test_PendingOwnerCannotBeIntroducedAsPendingManager() public {
        vm.prank(owner);
        encumbrance.transferOwnership(nextOwner);

        address[] memory managers = new address[](1);
        managers[0] = nextOwner;
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.RoleConflict.selector);
        encumbrance.proposeReleasePolicy(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, _composeSet(), managers
        );
    }

    function test_PostFreezeOnlyReductionsRevocationsAndOneWayHaltRemain() public {
        _activate(_managerSet());
        bytes32 committedComposeRoot = encumbrance.releaseComposeRoot();
        bytes32 committedManagerRoot = encumbrance.releaseManagerRoot();

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.ReleasePolicyFrozen.selector);
        encumbrance.proposeReleasePolicy(
            releaseAccountCommitment, maxAddBalanceWei, maxSpendWei, _composeSet(), _managerSet()
        );

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.RiskIncreaseRequiresNewRelease.selector);
        encumbrance.reduceFundingPolicy(maxAddBalanceWei + 1, maxSpendWei);

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.ZeroFundingPolicyLimit.selector);
        encumbrance.reduceFundingPolicy(0, 0);

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.SpendLimitExceedsAddBalanceLimit.selector);
        encumbrance.reduceFundingPolicy(1, 2);

        vm.prank(owner);
        encumbrance.reduceFundingPolicy(5 * POLICY_UNIT, POLICY_UNIT);
        assertEq(encumbrance.maxAddBalanceWei(), 5 * POLICY_UNIT);
        assertEq(encumbrance.maxSpendWei(), POLICY_UNIT);
        assertEq(encumbrance.releaseMaxAddBalanceWei(), maxAddBalanceWei);
        assertEq(encumbrance.releaseMaxSpendWei(), maxSpendWei);

        vm.prank(owner);
        encumbrance.revokeManager(manager);
        assertFalse(encumbrance.managers(manager));
        assertEq(encumbrance.managerCount(), 0);
        assertEq(encumbrance.releaseManagerRoot(), committedManagerRoot);
        assertTrue(encumbrance.managerRoot() != committedManagerRoot);

        vm.prank(owner);
        encumbrance.revokeComposeHash(composeHash);
        assertFalse(encumbrance.approvedComposeHashes(composeHash));
        assertEq(encumbrance.approvedComposeCount(), 0);
        assertEq(encumbrance.releaseComposeRoot(), committedComposeRoot);
        assertTrue(encumbrance.approvedComposeRoot() != committedComposeRoot);

        vm.prank(owner);
        encumbrance.setEmergencyHalt(true);
        assertTrue(encumbrance.emergencyHalted());

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.RiskIncreaseRequiresNewRelease.selector);
        encumbrance.setEmergencyHalt(false);
    }

    function test_ManagerAuthorizesBoundedPerOperationRecordsAfterRelease() public {
        _activate(_managerSet());

        vm.prank(manager);
        encumbrance.authorizeOperation(
            operationId, TinkerAccountEncumbrance.OperationKind.AddBalance, requester, composeHash, 5 * POLICY_UNIT
        );

        TinkerAccountEncumbrance.OperationRecord memory record = encumbrance.operation(operationId);
        assertEq(uint8(record.kind), uint8(TinkerAccountEncumbrance.OperationKind.AddBalance));
        assertEq(record.requester, requester);
        assertEq(record.authorizer, manager);
        assertEq(record.composeHash, composeHash);
        assertEq(record.amountWei, 5 * POLICY_UNIT);
        assertFalse(record.settled);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.AmountExceedsPolicy.selector);
        encumbrance.authorizeOperation(
            keccak256("over-cap"),
            TinkerAccountEncumbrance.OperationKind.SpendTinkerCompute,
            requester,
            composeHash,
            maxSpendWei + 1
        );
    }

    function test_PerOperationCapsTruthfullyPermitMultipleUniqueOperations() public {
        _activate(_managerSet());

        vm.startPrank(manager);
        encumbrance.authorizeOperation(
            keccak256("op-1"),
            TinkerAccountEncumbrance.OperationKind.SpendTinkerCompute,
            requester,
            composeHash,
            maxSpendWei
        );
        encumbrance.authorizeOperation(
            keccak256("op-2"),
            TinkerAccountEncumbrance.OperationKind.SpendTinkerCompute,
            requester,
            composeHash,
            maxSpendWei
        );
        vm.stopPrank();
    }

    function test_FrozenPolicyWithoutManagersHasNoOwnerExecutionFallback() public {
        _activate(_emptyManagerSet());

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.NotManager.selector);
        encumbrance.authorizeOperation(
            operationId, TinkerAccountEncumbrance.OperationKind.AddBalance, requester, composeHash, POLICY_UNIT
        );
    }

    function test_ApprovedManagerCanSettleExistingOperationAfterEmergencyHalt() public {
        _activate(_managerSet());

        vm.prank(manager);
        encumbrance.authorizeOperation(
            operationId, TinkerAccountEncumbrance.OperationKind.AddBalance, requester, composeHash, POLICY_UNIT
        );

        vm.prank(owner);
        encumbrance.setEmergencyHalt(true);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.EmergencyHalted.selector);
        encumbrance.authorizeOperation(
            keccak256("halted-operation"),
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            composeHash,
            POLICY_UNIT
        );

        vm.prank(manager);
        encumbrance.settleOperation(operationId, false, receiptHash);
        assertTrue(encumbrance.operation(operationId).settled);
    }

    function test_AuthorizationAndSettlementGuardsRemainFailClosed() public {
        _activate(_managerSet());

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.NotManager.selector);
        encumbrance.authorizeOperation(
            keccak256("owner-cannot-authorize"),
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            composeHash,
            POLICY_UNIT
        );

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.SelfApprovalNotAllowed.selector);
        encumbrance.authorizeOperation(
            operationId, TinkerAccountEncumbrance.OperationKind.AddBalance, manager, composeHash, POLICY_UNIT
        );

        vm.prank(manager);
        encumbrance.authorizeOperation(
            operationId, TinkerAccountEncumbrance.OperationKind.ManualPrefund, requester, composeHash, POLICY_UNIT
        );

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.DuplicateOperation.selector);
        encumbrance.authorizeOperation(
            operationId, TinkerAccountEncumbrance.OperationKind.ManualPrefund, requester, composeHash, POLICY_UNIT
        );

        vm.prank(stranger);
        vm.expectRevert(TinkerAccountEncumbrance.NotManager.selector);
        encumbrance.settleOperation(operationId, true, receiptHash);

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.NotManager.selector);
        encumbrance.settleOperation(operationId, true, receiptHash);

        vm.prank(manager);
        encumbrance.settleOperation(operationId, true, receiptHash);
        TinkerAccountEncumbrance.OperationRecord memory record = encumbrance.operation(operationId);
        assertTrue(record.settled);
        assertTrue(record.success);
        assertEq(record.receiptHash, receiptHash);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.AlreadySettled.selector);
        encumbrance.settleOperation(operationId, false, keccak256("other"));
    }

    function test_ManagerCannotMutateGovernanceOrSafetyPolicy() public {
        _activate(_managerSet());

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.reduceFundingPolicy(POLICY_UNIT, POLICY_UNIT);
        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.revokeComposeHash(composeHash);
        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.setEmergencyHalt(true);
    }
}
