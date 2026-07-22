// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {RoyaltyDistributor} from "../src/RoyaltyDistributor.sol";

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev Returns success from transfers without moving balances.
contract RoyaltyPhantomERC20 {
    mapping(address => uint256) public balanceOf;

    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return true;
    }
}

/// @dev Funds the distributor correctly, then returns success without paying a
///      claimant. Exact outbound balance-delta checks must preserve the claim.
contract RoyaltyOutboundPhantomERC20 is MockERC20 {
    function transfer(address, uint256) external pure override returns (bool) {
        return true;
    }
}

/// A malicious co-owner that re-enters `withdraw()` during its native payout to
/// try to drain a second time. The withdrawal lock and effects-before-interaction
/// ordering must prevent the second payout.
contract ReentrantRoyaltyClaimer {
    RoyaltyDistributor internal immutable dist;
    bool internal entered;
    uint256 public received;

    constructor(RoyaltyDistributor _dist) {
        dist = _dist;
    }

    function claim() external {
        dist.withdraw();
    }

    receive() external payable {
        received += msg.value;
        if (!entered) {
            entered = true;
            // Re-entrant withdraw must revert; swallow it so the single
            // legitimate payout can be asserted.
            try dist.withdraw() {} catch {}
        }
    }
}

contract RoyaltyDistributorTest is Test {
    RoyaltyDistributor internal dist;

    address internal payer = makeAddr("payer");
    address internal ownerA = makeAddr("ownerA");
    address internal ownerB = makeAddr("ownerB");
    bytes32 internal queryRef = keccak256("q1");

    function setUp() public {
        dist = new RoyaltyDistributor();
        vm.deal(payer, 100 ether);
    }

    function _owners() internal view returns (address[] memory owners) {
        owners = new address[](2);
        owners[0] = ownerA;
        owners[1] = ownerB;
    }

    function _amounts(uint256 a, uint256 b) internal pure returns (uint256[] memory amounts) {
        amounts = new uint256[](2);
        amounts[0] = a;
        amounts[1] = b;
    }

    // ── Native ─────────────────────────────────────────────────────────

    function test_DistributeNativeCreditsAndConserves() public {
        vm.prank(payer);
        dist.distributeNative{value: 1 ether}(queryRef, _owners(), _amounts(0.7 ether, 0.3 ether));

        assertEq(dist.pending(address(0), ownerA), 0.7 ether);
        assertEq(dist.pending(address(0), ownerB), 0.3 ether);
        assertEq(address(dist).balance, 1 ether);
    }

    function test_DistributeNativeRevertValueMismatch() public {
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ValueMismatch.selector);
        dist.distributeNative{value: 0.9 ether}(queryRef, _owners(), _amounts(0.7 ether, 0.3 ether));
    }

    function test_NativeWithdrawLifecycleConserves() public {
        vm.prank(payer);
        dist.distributeNative{value: 1 ether}(queryRef, _owners(), _amounts(0.7 ether, 0.3 ether));

        uint256 beforeA = ownerA.balance;
        vm.prank(ownerA);
        dist.withdraw();
        assertEq(ownerA.balance - beforeA, 0.7 ether);
        assertEq(dist.pending(address(0), ownerA), 0);

        vm.prank(ownerB);
        dist.withdraw();
        assertEq(ownerB.balance, 0.3 ether);
        assertEq(address(dist).balance, 0); // nothing stuck
    }

    function test_WithdrawNothingReverts() public {
        vm.prank(ownerA);
        vm.expectRevert(RoyaltyDistributor.NothingToWithdraw.selector);
        dist.withdraw();
    }

    function test_MultipleDistributionsAccumulate() public {
        vm.startPrank(payer);
        dist.distributeNative{value: 1 ether}(queryRef, _owners(), _amounts(0.6 ether, 0.4 ether));
        dist.distributeNative{value: 0.5 ether}(keccak256("q2"), _owners(), _amounts(0.3 ether, 0.2 ether));
        vm.stopPrank();
        assertEq(dist.pending(address(0), ownerA), 0.9 ether);
        assertEq(dist.pending(address(0), ownerB), 0.6 ether);
    }

    function test_QueryRefCannotBeDistributedTwice() public {
        vm.startPrank(payer);
        dist.distributeNative{value: 1 ether}(queryRef, _owners(), _amounts(0.6 ether, 0.4 ether));
        vm.expectRevert(RoyaltyDistributor.QueryAlreadyProcessed.selector);
        dist.distributeNative{value: 1 ether}(queryRef, _owners(), _amounts(0.6 ether, 0.4 ether));
        vm.stopPrank();

        assertTrue(dist.processedQueries(payer, queryRef));
        assertEq(address(dist).balance, 1 ether);
    }

    function test_UnrelatedDistributorCannotConsumePayerQueryRef() public {
        address attacker = makeAddr("attacker");
        address[] memory attackerOwners = new address[](1);
        attackerOwners[0] = attacker;
        uint256[] memory attackerAmounts = new uint256[](1);
        attackerAmounts[0] = 1;
        vm.deal(attacker, 1);

        vm.prank(attacker);
        dist.distributeNative{value: 1}(queryRef, attackerOwners, attackerAmounts);

        vm.prank(payer);
        dist.distributeNative{value: 1 ether}(queryRef, _owners(), _amounts(0.6 ether, 0.4 ether));

        assertTrue(dist.processedQueries(attacker, queryRef));
        assertTrue(dist.processedQueries(payer, queryRef));
        assertEq(dist.pending(address(0), attacker), 1);
        assertEq(dist.pending(address(0), ownerA), 0.6 ether);
        assertEq(dist.pending(address(0), ownerB), 0.4 ether);
    }

    function test_FailedDistributionDoesNotConsumeQueryRef() public {
        vm.startPrank(payer);
        vm.expectRevert(RoyaltyDistributor.ValueMismatch.selector);
        dist.distributeNative{value: 0.5 ether}(queryRef, _owners(), _amounts(0.6 ether, 0.4 ether));
        assertFalse(dist.processedQueries(payer, queryRef));

        dist.distributeNative{value: 1 ether}(queryRef, _owners(), _amounts(0.6 ether, 0.4 ether));
        vm.stopPrank();
        assertTrue(dist.processedQueries(payer, queryRef));
    }

    // ── ERC20 ──────────────────────────────────────────────────────────

    function test_DistributeERC20CreditsAndPullsFunds() public {
        MockERC20 usdc = new MockERC20();
        usdc.mint(payer, 1_000_000);
        vm.startPrank(payer);
        usdc.approve(address(dist), 1_000_000);
        dist.distributeERC20(queryRef, address(usdc), _owners(), _amounts(700_000, 300_000));
        vm.stopPrank();

        assertEq(dist.pending(address(usdc), ownerA), 700_000);
        assertEq(dist.pending(address(usdc), ownerB), 300_000);
        assertEq(usdc.balanceOf(address(dist)), 1_000_000);

        vm.prank(ownerA);
        dist.withdraw(address(usdc));
        vm.prank(ownerB);
        dist.withdraw(address(usdc));
        assertEq(usdc.balanceOf(ownerA), 700_000);
        assertEq(usdc.balanceOf(ownerB), 300_000);
        assertEq(usdc.balanceOf(address(dist)), 0);
    }

    function test_DistributeERC20RejectsZeroAddress() public {
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.InvalidToken.selector);
        dist.distributeERC20(queryRef, address(0), _owners(), _amounts(700_000, 300_000));
    }

    function test_DistributeERC20RejectsNonContract() public {
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.InvalidToken.selector);
        dist.distributeERC20(queryRef, makeAddr("not-a-token"), _owners(), _amounts(700_000, 300_000));
    }

    function test_DistributeERC20RejectsPhantomFunding() public {
        RoyaltyPhantomERC20 phantom = new RoyaltyPhantomERC20();

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.TokenAmountMismatch.selector);
        dist.distributeERC20(queryRef, address(phantom), _owners(), _amounts(700_000, 300_000));

        assertFalse(dist.processedQueries(payer, queryRef));
        assertEq(dist.pending(address(phantom), ownerA), 0);
        assertEq(dist.pending(address(phantom), ownerB), 0);
    }

    function test_WithdrawERC20RejectsPhantomPayoutAndPreservesClaim() public {
        RoyaltyOutboundPhantomERC20 phantom = new RoyaltyOutboundPhantomERC20();
        phantom.mint(payer, 1_000_000);
        vm.startPrank(payer);
        phantom.approve(address(dist), 1_000_000);
        dist.distributeERC20(queryRef, address(phantom), _owners(), _amounts(700_000, 300_000));
        vm.stopPrank();

        vm.prank(ownerA);
        vm.expectRevert(RoyaltyDistributor.TokenAmountMismatch.selector);
        dist.withdraw(address(phantom));

        assertEq(dist.pending(address(phantom), ownerA), 700_000);
        assertEq(phantom.balanceOf(ownerA), 0);
        assertEq(phantom.balanceOf(address(dist)), 1_000_000);
    }

    // ── Guards ─────────────────────────────────────────────────────────

    function test_LengthMismatchReverts() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.LengthMismatch.selector);
        dist.distributeNative{value: 1 ether}(queryRef, owners, amounts);
    }

    function test_EmptyDistributionReverts() public {
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.EmptyDistribution.selector);
        dist.distributeNative{value: 0}(queryRef, new address[](0), new uint256[](0));
    }

    function test_ZeroOwnerReverts() public {
        address[] memory owners = new address[](1);
        owners[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ZeroOwner.selector);
        dist.distributeNative{value: 1 ether}(queryRef, owners, amounts);
    }

    function test_DistributorCannotBeItsOwnRoyaltyOwner() public {
        address[] memory owners = new address[](1);
        owners[0] = address(dist);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.SelfOwner.selector);
        dist.distributeNative{value: 1 ether}(queryRef, owners, amounts);
    }

    function test_ZeroQueryReferenceRevertsWithoutConsumingReplaySlot() public {
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ZeroQueryRef.selector);
        dist.distributeNative{value: 1 ether}(bytes32(0), _owners(), _amounts(0.7 ether, 0.3 ether));
        assertFalse(dist.processedQueries(payer, bytes32(0)));
    }

    function test_ZeroAmountReverts() public {
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ZeroAmount.selector);
        dist.distributeNative{value: 0.7 ether}(queryRef, _owners(), _amounts(0.7 ether, 0));
    }

    // ── Conservation fuzz ──────────────────────────────────────────────

    function testFuzz_NativeConservation(uint256 a, uint256 b) public {
        a = bound(a, 1, 10 ether);
        b = bound(b, 1, 10 ether);
        uint256 total = a + b;
        vm.deal(payer, total);
        vm.prank(payer);
        dist.distributeNative{value: total}(queryRef, _owners(), _amounts(a, b));

        vm.prank(ownerA);
        dist.withdraw();
        vm.prank(ownerB);
        dist.withdraw();
        assertEq(ownerA.balance + ownerB.balance, total);
        assertEq(address(dist).balance, 0);
    }

    // ── Reentrancy ─────────────────────────────────────────────────────
    function test_Withdraw_ReentrancyCannotDoublePay() public {
        ReentrantRoyaltyClaimer attacker = new ReentrantRoyaltyClaimer(dist);
        address[] memory owners = new address[](2);
        owners[0] = address(attacker);
        owners[1] = ownerB;
        // Credit the attacker 3 ether and ownerB 1 ether.
        vm.prank(payer);
        dist.distributeNative{value: 4 ether}(queryRef, owners, _amounts(3 ether, 1 ether));

        attacker.claim();

        // The reentrant second withdraw was blocked: the attacker got exactly
        // its single credit, its pending is zero, and ownerB's funds are untouched
        // (the contract still holds them). No double-pay / drain.
        assertEq(attacker.received(), 3 ether);
        assertEq(dist.pending(address(0), address(attacker)), 0);
        assertEq(address(dist).balance, 1 ether);
        assertEq(dist.pending(address(0), ownerB), 1 ether);
    }
}
