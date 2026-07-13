// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

contract TinkerAccountEncumbranceTest is Test {
    TinkerAccountEncumbrance internal encumbrance;

    address internal owner = makeAddr("owner");
    address internal manager = makeAddr("manager");
    address internal requester = makeAddr("requester");
    address internal stranger = makeAddr("stranger");

    bytes32 internal accountCommitment = keccak256("tinker-account");
    bytes32 internal composeHash = keccak256("compose-v1");
    bytes32 internal nextComposeHash = keccak256("compose-v2");
    bytes32 internal operationId = keccak256("operation-1");
    bytes32 internal receiptHash = keccak256("bounded-receipt");

    uint256 internal maxAddBalanceWei = 10 ether;
    uint256 internal maxSpendWei = 2 ether;

    function setUp() public {
        vm.prank(owner);
        encumbrance = new TinkerAccountEncumbrance(
            owner,
            accountCommitment,
            composeHash,
            maxAddBalanceWei,
            maxSpendWei
        );
    }

    function test_InitialPolicy() public view {
        assertEq(encumbrance.owner(), owner);
        assertEq(encumbrance.accountCommitment(), accountCommitment);
        assertEq(encumbrance.maxAddBalanceWei(), maxAddBalanceWei);
        assertEq(encumbrance.maxSpendWei(), maxSpendWei);
        assertTrue(encumbrance.approvedComposeHashes(composeHash));
        assertFalse(encumbrance.emergencyHalted());
    }

    function test_OwnerCanDelegateManagerAndManagerCanAuthorizeWithinCaps() public {
        vm.prank(owner);
        encumbrance.setManager(manager, true);

        vm.prank(manager);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            composeHash,
            5 ether
        );

        TinkerAccountEncumbrance.OperationRecord memory record = encumbrance.operation(operationId);
        assertEq(uint8(record.kind), uint8(TinkerAccountEncumbrance.OperationKind.AddBalance));
        assertEq(record.requester, requester);
        assertEq(record.authorizer, manager);
        assertEq(record.composeHash, composeHash);
        assertEq(record.amountWei, 5 ether);
        assertFalse(record.settled);
    }

    function test_AuthorizerCannotSelfApprove() public {
        vm.prank(owner);
        encumbrance.setManager(manager, true);

        // A manager cannot authorize an operation where they are also the
        // requester (non-self-approval, enforced on-chain).
        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.SelfApprovalNotAllowed.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            manager,
            composeHash,
            1 ether
        );

        // The owner cannot self-approve either.
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.SelfApprovalNotAllowed.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            owner,
            composeHash,
            1 ether
        );
    }

    function test_ManagerCannotExceedOwnerGrantedAuthority() public {
        vm.prank(owner);
        encumbrance.setManager(manager, true);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.AmountExceedsPolicy.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            composeHash,
            maxAddBalanceWei + 1
        );

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.AmountExceedsPolicy.selector);
        encumbrance.authorizeOperation(
            keccak256("operation-2"),
            TinkerAccountEncumbrance.OperationKind.SpendTinkerCompute,
            requester,
            composeHash,
            maxSpendWei + 1
        );
    }

    function test_ManagerCannotChangePolicyMeasurementsManagersOrHalt() public {
        vm.prank(owner);
        encumbrance.setManager(manager, true);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.setManager(stranger, true);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.setFundingPolicy(100 ether, 100 ether);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.approveComposeHash(nextComposeHash);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwner.selector);
        encumbrance.setEmergencyHalt(true);
    }

    function test_ComposePolicyAndMeasurementFreeze() public {
        vm.prank(owner);
        encumbrance.approveComposeHash(nextComposeHash);
        assertTrue(encumbrance.approvedComposeHashes(nextComposeHash));

        vm.prank(owner);
        encumbrance.revokeComposeHash(nextComposeHash);
        assertFalse(encumbrance.approvedComposeHashes(nextComposeHash));

        vm.prank(owner);
        encumbrance.freezeMeasurements();

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.MeasurementsFrozen.selector);
        encumbrance.approveComposeHash(nextComposeHash);
    }

    function test_UnapprovedComposeHashAndEmergencyHaltRejectOperations() public {
        vm.prank(owner);
        encumbrance.setManager(manager, true);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.ComposeHashNotApproved.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            nextComposeHash,
            1 ether
        );

        vm.prank(owner);
        encumbrance.setEmergencyHalt(true);

        vm.prank(manager);
        vm.expectRevert(TinkerAccountEncumbrance.EmergencyHalted.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            composeHash,
            1 ether
        );
    }

    function test_AddPaymentMethodMustHaveZeroAmount() public {
        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.NonZeroAmountForPaymentMethod.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddPaymentMethod,
            requester,
            composeHash,
            1
        );

        vm.prank(owner);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddPaymentMethod,
            requester,
            composeHash,
            0
        );
    }

    function test_DuplicateAndSettlementGuards() public {
        vm.prank(owner);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.ManualPrefund,
            requester,
            composeHash,
            1 ether
        );

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.DuplicateOperation.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.ManualPrefund,
            requester,
            composeHash,
            1 ether
        );

        vm.prank(owner);
        encumbrance.settleOperation(operationId, true, receiptHash);

        TinkerAccountEncumbrance.OperationRecord memory record = encumbrance.operation(operationId);
        assertTrue(record.settled);
        assertTrue(record.success);
        assertEq(record.receiptHash, receiptHash);

        vm.prank(owner);
        vm.expectRevert(TinkerAccountEncumbrance.AlreadySettled.selector);
        encumbrance.settleOperation(operationId, false, keccak256("other"));
    }

    function test_UnauthorizedCallerCannotAuthorizeOrSettle() public {
        vm.prank(stranger);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwnerOrManager.selector);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            composeHash,
            1 ether
        );

        vm.prank(owner);
        encumbrance.authorizeOperation(
            operationId,
            TinkerAccountEncumbrance.OperationKind.AddBalance,
            requester,
            composeHash,
            1 ether
        );

        vm.prank(stranger);
        vm.expectRevert(TinkerAccountEncumbrance.NotOwnerOrManager.selector);
        encumbrance.settleOperation(operationId, true, receiptHash);
    }
}
