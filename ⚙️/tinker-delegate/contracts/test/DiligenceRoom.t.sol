// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DiligenceRoom} from "../src/DiligenceRoom.sol";

contract RevertingReceiver {
    DiligenceRoom internal immutable room;

    constructor(DiligenceRoom _room) {
        room = _room;
    }

    function createDeal(
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity
    ) external returns (uint256) {
        return room.createDeal(reservePrice, expiry, artifactHash, teeIdentity);
    }

    function withdraw() external {
        room.withdraw();
    }

    receive() external payable {
        revert("nope");
    }
}

/// @dev Attempts to re-enter withdraw() on receiving its payout; used to prove
///      the checks-effects-interactions ordering blocks double-withdrawal.
contract ReentrantWithdrawer {
    DiligenceRoom internal immutable room;
    bool internal entered;
    uint256 public received;

    constructor(DiligenceRoom _room) {
        room = _room;
    }

    function fund(uint256 dealId, uint256 amount) external {
        room.fundDeal{value: amount}(dealId);
    }

    function reject(uint256 dealId) external {
        room.rejectDeal(dealId);
    }

    function attackWithdraw() external {
        room.withdraw();
    }

    receive() external payable {
        received += msg.value;
        if (!entered) {
            entered = true;
            // Re-entrant withdraw must find a zeroed balance and revert; swallow
            // it so we can assert the single legitimate payout landed.
            try room.withdraw() {} catch {}
        }
    }
}

/// @dev Minimal ERC20 (USDC-like, 6 decimals, returns bool) for settlement tests.
contract MockERC20 {
    string public name = "Mock USDC";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount; // underflows/reverts on insufficient balance
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount; // reverts without approval
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract DiligenceRoomTest is Test {
    DiligenceRoom public room;
    bytes32 internal constant RESULT_AUTHORIZATION_TYPEHASH = keccak256(
        "DiligenceRoomResultAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,uint8 scoreBand,uint256 computeCost,bytes32 resultHash,uint256 authorizationExpiry)"
    );

    address dev = address(this);
    address seller = makeAddr("seller");
    address buyer = makeAddr("buyer");
    address tee = makeAddr("tee");
    uint256 verifierPk = 0xA11CE;
    address verifier;

    uint256 reservePrice = 0.5 ether;
    uint256 budgetCap = 2 ether;
    uint256 expiry;
    bytes32 artifactHash = keccak256("test-artifact");
    bytes32 composeHash = keccak256("delegate-compose-v1");

    function setUp() public {
        verifier = vm.addr(verifierPk);
        room = new DiligenceRoom(verifier);
        expiry = block.timestamp + 1 days;
        vm.deal(buyer, 10 ether);
    }

    // ── Helpers ────────────────────────────────────────────────────────

    function _createDeal() internal returns (uint256) {
        vm.prank(seller);
        return room.createDeal(reservePrice, expiry, artifactHash, tee);
    }

    function _fundDeal(uint256 dealId) internal {
        vm.prank(buyer);
        room.fundDeal{value: budgetCap}(dealId);
    }

    function _submitResult(
        uint256 dealId,
        DiligenceRoom.ScoreBand band,
        uint256 computeCost
    ) internal {
        bytes32 resultHash = keccak256("result");
        uint256 authorizationExpiry = block.timestamp + 1 hours;
        vm.prank(tee);
        room.submitResult(
            dealId,
            band,
            computeCost,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(dealId, band, computeCost, resultHash, authorizationExpiry)
        );
    }

    function _authorizationSignature(
        uint256 dealId,
        DiligenceRoom.ScoreBand band,
        uint256 computeCost,
        bytes32 resultHash,
        uint256 authorizationExpiry
    ) internal view returns (bytes memory) {
        bytes32 digest = _authorizationDigest(
            dealId,
            tee,
            composeHash,
            band,
            computeCost,
            resultHash,
            authorizationExpiry
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierPk, _ethSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _authorizationDigest(
        uint256 dealId,
        address teeIdentity,
        bytes32 resultComposeHash,
        DiligenceRoom.ScoreBand band,
        uint256 computeCost,
        bytes32 resultHash,
        uint256 authorizationExpiry
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                RESULT_AUTHORIZATION_TYPEHASH,
                block.chainid,
                address(room),
                dealId,
                teeIdentity,
                resultComposeHash,
                uint8(band),
                computeCost,
                resultHash,
                authorizationExpiry
            )
        );
    }

    function _ethSignedMessageHash(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }

    // ── Creation ───────────────────────────────────────────────────────

    function test_CreateDeal() public {
        uint256 id = _createDeal();
        assertEq(id, 0);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(d.seller, seller);
        assertEq(d.reservePrice, reservePrice);
        assertEq(d.expiry, expiry);
        assertEq(d.artifactHash, artifactHash);
        assertEq(d.teeIdentity, tee);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Created));
    }

    function test_CreateDeal_RevertInvalidExpiry() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.InvalidExpiry.selector);
        room.createDeal(reservePrice, block.timestamp, artifactHash, tee);
    }

    function test_CreateDeal_RevertZeroArtifactHash() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.ZeroArtifactHash.selector);
        room.createDeal(reservePrice, expiry, bytes32(0), tee);
    }

    function test_CreateDeal_RevertZeroTEEIdentity() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.ZeroTEEIdentity.selector);
        room.createDeal(reservePrice, expiry, artifactHash, address(0));
    }

    function test_DealCountIncrements() public {
        _createDeal();
        _createDeal();
        assertEq(room.dealCount(), 2);
    }

    // ── Funding ────────────────────────────────────────────────────────

    function test_FundDeal() public {
        uint256 id = _createDeal();
        _fundDeal(id);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(d.buyer, buyer);
        assertEq(d.budgetCap, budgetCap);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Funded));
    }

    function test_FundDeal_RevertWrongState() public {
        uint256 id = _createDeal();
        _fundDeal(id);

        // Try to fund again
        vm.prank(buyer);
        vm.expectRevert();
        room.fundDeal{value: 1 ether}(id);
    }

    function test_FundDeal_RevertExpired() public {
        uint256 id = _createDeal();
        vm.warp(expiry + 1);

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.AlreadyExpired.selector);
        room.fundDeal{value: budgetCap}(id);
    }

    function test_FundDeal_RevertZeroValue() public {
        uint256 id = _createDeal();

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.InsufficientFunding.selector);
        room.fundDeal{value: 0}(id);
    }

    // ── Evaluation ─────────────────────────────────────────────────────

    function test_SubmitResult() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Evaluated));
        assertEq(uint8(d.scoreBand), uint8(DiligenceRoom.ScoreBand.High));
        assertEq(d.computeCost, 0.1 ether);
        assertEq(d.fee, 0.001 ether); // 1% of 0.1
        assertEq(d.resultComposeHash, composeHash);
    }

    function test_SubmitResult_RevertNotTEE() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("r");
        uint256 authorizationExpiry = block.timestamp + 1 hours;

        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotTEE.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(
                id,
                DiligenceRoom.ScoreBand.High,
                0.1 ether,
                resultHash,
                authorizationExpiry
            )
        );
    }

    function test_SubmitResult_RevertWrongState() public {
        uint256 id = _createDeal();
        // Not funded yet
        bytes32 resultHash = keccak256("r");
        uint256 authorizationExpiry = block.timestamp + 1 hours;
        vm.prank(tee);
        vm.expectRevert();
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(
                id,
                DiligenceRoom.ScoreBand.High,
                0.1 ether,
                resultHash,
                authorizationExpiry
            )
        );
    }

    function test_SubmitResult_RevertComputeCostOverBudget() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("r");
        uint256 authorizationExpiry = block.timestamp + 1 hours;

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComputeCostOverBudget.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            1.99 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(
                id,
                DiligenceRoom.ScoreBand.High,
                1.99 ether,
                resultHash,
                authorizationExpiry
            )
        );
    }

    function test_SubmitResult_RevertZeroComposeHash() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("r");
        uint256 authorizationExpiry = block.timestamp + 1 hours;

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ZeroComposeHash.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            bytes32(0),
            authorizationExpiry,
            _authorizationSignature(
                id,
                DiligenceRoom.ScoreBand.High,
                0.1 ether,
                resultHash,
                authorizationExpiry
            )
        );
    }

    function test_SubmitResult_RevertExpiredAuthorization() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("r");
        uint256 authorizationExpiry = block.timestamp - 1;

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.AuthorizationExpired.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(
                id,
                DiligenceRoom.ScoreBand.High,
                0.1 ether,
                resultHash,
                authorizationExpiry
            )
        );
    }

    function test_SubmitResult_RevertInvalidAuthorizationSigner() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("r");
        uint256 authorizationExpiry = block.timestamp + 1 hours;
        bytes32 digest = _authorizationDigest(
            id,
            tee,
            composeHash,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            authorizationExpiry
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            0xB0B,
            _ethSignedMessageHash(digest)
        );

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            abi.encodePacked(r, s, v)
        );
    }

    // ── On-chain compose-approval gate ─────────────────────────────────

    function test_ComposeApprovalDefaultsOff() public {
        assertEq(room.composeApprovalRequired(), false);
        assertEq(room.approvedComposeHashes(composeHash), false);
        // With the gate off, submission works even for an unapproved compose.
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Evaluated));
    }

    function test_ApproveComposeHash_OnlyDeveloper() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.approveComposeHash(composeHash);
    }

    function test_SetComposeApprovalRequired_OnlyDeveloper() public {
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.setComposeApprovalRequired(true);
    }

    function test_ApproveComposeHash_RevertZero() public {
        vm.expectRevert(DiligenceRoom.ZeroComposeHash.selector);
        room.approveComposeHash(bytes32(0));
    }

    function test_SubmitResult_RevertComposeNotApprovedWhenRequired() public {
        room.setComposeApprovalRequired(true);
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("result");
        uint256 authorizationExpiry = block.timestamp + 1 hours;
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, resultHash, authorizationExpiry)
        );
    }

    function test_SubmitResult_SucceedsWhenComposeApproved() public {
        room.setComposeApprovalRequired(true);
        room.approveComposeHash(composeHash);
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Evaluated));
        assertEq(room.getDeal(id).resultComposeHash, composeHash);
    }

    function test_RevokeComposeHash_BlocksSubmit() public {
        room.setComposeApprovalRequired(true);
        room.approveComposeHash(composeHash);
        room.revokeComposeHash(composeHash);
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("result");
        uint256 authorizationExpiry = block.timestamp + 1 hours;
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, resultHash, authorizationExpiry)
        );
    }

    // ── On-chain TEE-identity binding gate ─────────────────────────────

    function test_TeeIdentityApprovalDefaultsOff() public {
        assertEq(room.teeIdentityApprovalRequired(), false);
        assertEq(room.teeIdentityComposeHash(tee), bytes32(0));
        // Off: createDeal accepts any teeIdentity (backward compatible).
        uint256 id = _createDeal();
        assertEq(room.getDeal(id).teeIdentity, tee);
    }

    function test_ApproveTeeIdentity_OnlyDeveloper() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.approveTeeIdentity(tee, composeHash);
    }

    function test_ApproveTeeIdentity_RevertZeroAddressOrHash() public {
        vm.expectRevert(DiligenceRoom.ZeroTEEIdentity.selector);
        room.approveTeeIdentity(address(0), composeHash);
        vm.expectRevert(DiligenceRoom.ZeroComposeHash.selector);
        room.approveTeeIdentity(tee, bytes32(0));
    }

    function test_CreateDeal_RevertTeeIdentityNotApprovedWhenRequired() public {
        room.setTeeIdentityApprovalRequired(true);
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.TeeIdentityNotApproved.selector);
        room.createDeal(reservePrice, expiry, artifactHash, tee);
    }

    function test_CreateDeal_SucceedsWhenTeeIdentityApproved() public {
        room.setTeeIdentityApprovalRequired(true);
        room.approveTeeIdentity(tee, composeHash);
        uint256 id = _createDeal();
        assertEq(room.getDeal(id).teeIdentity, tee);
    }

    function test_SubmitResult_SucceedsWhenIdentityComposeMatches() public {
        room.setTeeIdentityApprovalRequired(true);
        room.approveTeeIdentity(tee, composeHash);
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Evaluated));
    }

    function test_SubmitResult_RevertWhenIdentityComposeMismatch() public {
        // Identity bound to a DIFFERENT measurement than the one submitted.
        bytes32 otherCompose = keccak256("delegate-compose-v2");
        room.approveTeeIdentity(tee, otherCompose);
        room.setTeeIdentityApprovalRequired(true);
        uint256 id = _createDeal();
        _fundDeal(id);
        bytes32 resultHash = keccak256("result");
        uint256 authorizationExpiry = block.timestamp + 1 hours;
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComposeHashIdentityMismatch.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, resultHash, authorizationExpiry)
        );
    }

    function test_RevokeTeeIdentity_BlocksCreate() public {
        room.setTeeIdentityApprovalRequired(true);
        room.approveTeeIdentity(tee, composeHash);
        room.revokeTeeIdentity(tee);
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.TeeIdentityNotApproved.selector);
        room.createDeal(reservePrice, expiry, artifactHash, tee);
    }

    function test_SetTeeIdentityApprovalRequired_OnlyDeveloper() public {
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.setTeeIdentityApprovalRequired(true);
    }

    // ── Accept ─────────────────────────────────────────────────────────

    function test_AcceptDeal() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        uint256 sellerBefore = seller.balance;
        uint256 devBefore = dev.balance;
        uint256 buyerBefore = buyer.balance;

        uint256 dealPayment = 1 ether;
        vm.prank(buyer);
        room.acceptDeal(id, dealPayment);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Accepted));

        uint256 devPayment = 0.1 ether + 0.001 ether;
        uint256 expectedRefund = budgetCap - dealPayment - devPayment;

        assertEq(room.pendingWithdrawals(address(0), seller), dealPayment);
        assertEq(room.pendingWithdrawals(address(0), dev), devPayment);
        assertEq(room.pendingWithdrawals(address(0), buyer), expectedRefund);

        vm.prank(seller);
        room.withdraw();
        room.withdraw();
        vm.prank(buyer);
        room.withdraw();

        assertEq(seller.balance - sellerBefore, dealPayment);
        assertEq(dev.balance - devBefore, devPayment);
        assertEq(buyer.balance - buyerBefore, expectedRefund);
    }

    function test_AcceptDeal_RevertingSellerCannotBlockSettlement() public {
        RevertingReceiver revertingSeller = new RevertingReceiver(room);
        uint256 id = revertingSeller.createDeal(reservePrice, expiry, artifactHash, tee);

        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        vm.prank(buyer);
        room.acceptDeal(id, 1 ether);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Accepted));
        assertEq(room.pendingWithdrawals(address(0), address(revertingSeller)), 1 ether);

        vm.expectRevert(DiligenceRoom.TransferFailed.selector);
        revertingSeller.withdraw();
        assertEq(room.pendingWithdrawals(address(0), address(revertingSeller)), 1 ether);
    }

    function test_AcceptDeal_RevertBelowReserve() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.PaymentBelowReserve.selector);
        room.acceptDeal(id, 0.1 ether); // below 0.5 ether reserve
    }

    function test_AcceptDeal_RevertAboveBudget() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.PaymentAboveBudget.selector);
        room.acceptDeal(id, budgetCap); // dealPayment + devPayment > budgetCap
    }

    function test_AcceptDeal_RevertNotBuyer() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotBuyer.selector);
        room.acceptDeal(id, 1 ether);
    }

    // ── Reject ─────────────────────────────────────────────────────────

    function test_RejectDeal() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.Negligible, 0.05 ether);

        uint256 devBefore = dev.balance;
        uint256 buyerBefore = buyer.balance;

        vm.prank(buyer);
        room.rejectDeal(id);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Rejected));

        uint256 devPayment = 0.05 ether + 0.0005 ether;
        uint256 buyerRefund = budgetCap - devPayment;

        assertEq(room.pendingWithdrawals(address(0), dev), devPayment);
        assertEq(room.pendingWithdrawals(address(0), buyer), buyerRefund);

        room.withdraw();
        vm.prank(buyer);
        room.withdraw();

        assertEq(dev.balance - devBefore, devPayment);
        assertEq(buyer.balance - buyerBefore, buyerRefund);
    }

    // ── Expire ─────────────────────────────────────────────────────────

    function test_ExpireDeal_Created() public {
        uint256 id = _createDeal();
        vm.warp(expiry + 1);

        room.expireDeal(id);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Expired));
    }

    function test_ExpireDeal_Funded() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        vm.warp(expiry + 1);

        uint256 buyerBefore = buyer.balance;
        room.expireDeal(id);

        assertEq(room.pendingWithdrawals(address(0), buyer), budgetCap);

        vm.prank(buyer);
        room.withdraw();
        assertEq(buyer.balance - buyerBefore, budgetCap);
    }

    function test_ExpireDeal_Evaluated() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.Low, 0.02 ether);

        vm.warp(expiry + 1);

        uint256 devBefore = dev.balance;
        uint256 buyerBefore = buyer.balance;

        room.expireDeal(id);

        uint256 devPayment = 0.02 ether + 0.0002 ether;
        uint256 buyerRefund = budgetCap - devPayment;

        assertEq(room.pendingWithdrawals(address(0), dev), devPayment);
        assertEq(room.pendingWithdrawals(address(0), buyer), buyerRefund);

        room.withdraw();
        vm.prank(buyer);
        room.withdraw();

        assertEq(dev.balance - devBefore, devPayment);
        assertEq(buyer.balance - buyerBefore, buyerRefund);
    }

    function test_ExpireDeal_RevertNotExpired() public {
        uint256 id = _createDeal();
        _fundDeal(id);

        vm.expectRevert(DiligenceRoom.NotExpired.selector);
        room.expireDeal(id);
    }

    function test_ExpireDeal_RevertAlreadyResolved() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        vm.prank(buyer);
        room.acceptDeal(id, 1 ether);

        vm.warp(expiry + 1);
        vm.expectRevert();
        room.expireDeal(id);
    }

    function test_Withdraw_RevertNothingToWithdraw() public {
        vm.expectRevert(DiligenceRoom.NothingToWithdraw.selector);
        room.withdraw();
    }

    // ── Full lifecycle ─────────────────────────────────────────────────

    function test_FullLifecycle_Accept() public {
        // 1. Seller creates deal
        uint256 id = _createDeal();

        // 2. Buyer funds
        _fundDeal(id);

        // 3. TEE evaluates
        _submitResult(id, DiligenceRoom.ScoreBand.Exceptional, 0.2 ether);

        // 4. Buyer accepts at reserve price
        vm.prank(buyer);
        room.acceptDeal(id, reservePrice);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Accepted));
    }

    function test_FullLifecycle_Reject() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.Negligible, 0.01 ether);

        vm.prank(buyer);
        room.rejectDeal(id);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Rejected));
    }

    // ── Fuzz ───────────────────────────────────────────────────────────

    function testFuzz_Settlement(uint256 payment, uint256 compute) public {
        // Bound inputs to reasonable ranges
        payment = bound(payment, reservePrice, 1 ether);
        compute = bound(compute, 0, 0.3 ether);
        uint256 fee = (compute * 100) / 10000;

        // Ensure total doesn't exceed budget
        vm.assume(payment + compute + fee <= budgetCap);

        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, compute);

        uint256 totalBefore = seller.balance + dev.balance + buyer.balance;

        vm.prank(buyer);
        room.acceptDeal(id, payment);

        uint256 totalPending =
            room.pendingWithdrawals(address(0), seller) +
            room.pendingWithdrawals(address(0), dev) +
            room.pendingWithdrawals(address(0), buyer);

        assertEq(totalPending, budgetCap);
        assertEq(seller.balance + dev.balance + buyer.balance - totalBefore, 0);
    }

    // ── Settlement-path edge cases ─────────────────────────────────────

    function test_SubmitResult_RevertDoubleSubmit() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        // Deal is now Evaluated; a second submit must revert on the state guard.
        bytes32 resultHash = keccak256("result2");
        uint256 authorizationExpiry = block.timestamp + 1 hours;
        vm.prank(tee);
        vm.expectRevert(
            abi.encodeWithSelector(
                DiligenceRoom.InvalidState.selector,
                DiligenceRoom.State.Funded,
                DiligenceRoom.State.Evaluated
            )
        );
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            resultHash,
            composeHash,
            authorizationExpiry,
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, resultHash, authorizationExpiry)
        );
    }

    function test_SubmitResult_RevertCrossDealAuthorizationReplay() public {
        uint256 dealA = _createDeal();
        _fundDeal(dealA);
        uint256 dealB = _createDeal();
        _fundDeal(dealB);

        DiligenceRoom.ScoreBand band = DiligenceRoom.ScoreBand.High;
        uint256 computeCost = 0.1 ether;
        bytes32 resultHash = keccak256("result");
        uint256 authorizationExpiry = block.timestamp + 1 hours;

        // An authorization signed for dealA binds dealId in its digest, so
        // replaying it on dealB recovers a non-verifier signer and is rejected.
        bytes memory sigForDealA =
            _authorizationSignature(dealA, band, computeCost, resultHash, authorizationExpiry);
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            dealB,
            band,
            computeCost,
            resultHash,
            composeHash,
            authorizationExpiry,
            sigForDealA
        );
    }

    function test_Withdraw_ReentrancyCannotDoublePay() public {
        ReentrantWithdrawer attacker = new ReentrantWithdrawer(room);
        vm.deal(address(attacker), budgetCap);

        uint256 id = _createDeal();
        attacker.fund(id, budgetCap); // attacker is the buyer
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, 0.1 ether);
        attacker.reject(id); // accrues a refund to the attacker

        uint256 refund = room.pendingWithdrawals(address(0), address(attacker));
        assertGt(refund, 0);
        uint256 devPending = room.pendingWithdrawals(address(0), dev);

        attacker.attackWithdraw();

        // The attacker receives exactly its refund once; the re-entrant call
        // found a zeroed balance and could not double-withdraw.
        assertEq(attacker.received(), refund);
        assertEq(room.pendingWithdrawals(address(0), address(attacker)), 0);
        // Only the developer's still-unclaimed payout remains escrowed.
        assertEq(address(room).balance, devPending);
    }

    // ── ERC20 / stablecoin settlement ──────────────────────────────────

    // Token deals use a 6-decimal (USDC-scale) reserve, not the ether fixture.
    uint256 internal constant TOKEN_RESERVE = 500_000; // 0.5 USDC

    function _createTokenDeal(address token) internal returns (uint256) {
        vm.prank(seller);
        return room.createDeal(TOKEN_RESERVE, expiry, artifactHash, tee, token);
    }

    function _fundTokenDeal(MockERC20 token, uint256 id, uint256 cap) internal {
        token.mint(buyer, cap);
        vm.startPrank(buyer);
        token.approve(address(room), cap);
        room.fundDealERC20(id, cap);
        vm.stopPrank();
    }

    function test_ERC20_FullLifecycle_Accept() public {
        MockERC20 usdc = new MockERC20();
        uint256 cap = 2_000_000;     // 2 USDC (6 decimals)
        uint256 compute = 100_000;   // 0.1 USDC
        uint256 payment = 1_000_000; // 1 USDC to seller
        uint256 id = _createTokenDeal(address(usdc));
        _fundTokenDeal(usdc, id, cap);

        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(d.paymentToken, address(usdc));
        assertEq(d.budgetCap, cap);
        assertEq(usdc.balanceOf(address(room)), cap);

        _submitResult(id, DiligenceRoom.ScoreBand.High, compute);
        vm.prank(buyer);
        room.acceptDeal(id, payment);

        uint256 fee = (compute * 100) / 10000;
        assertEq(room.pendingWithdrawals(address(usdc), seller), payment);
        assertEq(room.pendingWithdrawals(address(usdc), dev), compute + fee);
        assertEq(room.pendingWithdrawals(address(usdc), buyer), cap - payment - compute - fee);
        // Native balances must be untouched for a token deal.
        assertEq(room.pendingWithdrawals(address(0), seller), 0);

        vm.prank(seller);
        room.withdraw(address(usdc));
        assertEq(usdc.balanceOf(seller), payment);
        assertEq(usdc.balanceOf(address(room)), cap - payment);
    }

    function test_ERC20_Reject_PaysDeveloperOnly() public {
        MockERC20 usdc = new MockERC20();
        uint256 cap = 2_000_000;
        uint256 compute = 100_000;
        uint256 id = _createTokenDeal(address(usdc));
        _fundTokenDeal(usdc, id, cap);
        _submitResult(id, DiligenceRoom.ScoreBand.Low, compute);

        vm.prank(buyer);
        room.rejectDeal(id);

        uint256 fee = (compute * 100) / 10000;
        assertEq(room.pendingWithdrawals(address(usdc), dev), compute + fee);
        assertEq(room.pendingWithdrawals(address(usdc), buyer), cap - compute - fee);
        assertEq(room.pendingWithdrawals(address(usdc), seller), 0);
    }

    function test_ERC20_Expire_RefundsBuyer() public {
        MockERC20 usdc = new MockERC20();
        uint256 cap = 2_000_000;
        uint256 id = _createTokenDeal(address(usdc));
        _fundTokenDeal(usdc, id, cap);

        vm.warp(expiry + 1);
        room.expireDeal(id);
        // No evaluation happened, so the buyer is refunded the full cap.
        assertEq(room.pendingWithdrawals(address(usdc), buyer), cap);
        vm.prank(buyer);
        room.withdraw(address(usdc));
        assertEq(usdc.balanceOf(buyer), cap);
    }

    function test_ERC20_SettlementConservation() public {
        MockERC20 usdc = new MockERC20();
        uint256 cap = 2_000_000;
        uint256 compute = 250_000;
        uint256 payment = 900_000;
        uint256 id = _createTokenDeal(address(usdc));
        _fundTokenDeal(usdc, id, cap);
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, compute);
        vm.prank(buyer);
        room.acceptDeal(id, payment);

        uint256 total = room.pendingWithdrawals(address(usdc), seller)
            + room.pendingWithdrawals(address(usdc), dev)
            + room.pendingWithdrawals(address(usdc), buyer);
        assertEq(total, cap);
        assertEq(usdc.balanceOf(address(room)), cap);
    }

    function test_FundDeal_RevertNativeOnTokenDeal() public {
        MockERC20 usdc = new MockERC20();
        uint256 id = _createTokenDeal(address(usdc));
        vm.deal(buyer, 1 ether);
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.TokenMismatch.selector);
        room.fundDeal{value: 1 ether}(id);
    }

    function test_FundDealERC20_RevertTokenOnNativeDeal() public {
        uint256 id = _createDeal(); // native ETH deal
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.TokenMismatch.selector);
        room.fundDealERC20(id, 1_000_000);
    }

    function test_FundDealERC20_RevertWithoutApproval() public {
        MockERC20 usdc = new MockERC20();
        uint256 id = _createTokenDeal(address(usdc));
        usdc.mint(buyer, 2_000_000);
        vm.prank(buyer); // no approve()
        vm.expectRevert(DiligenceRoom.TransferFailed.selector);
        room.fundDealERC20(id, 2_000_000);
    }

    function test_Withdraw_Token_RevertNothingToWithdraw() public {
        MockERC20 usdc = new MockERC20();
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NothingToWithdraw.selector);
        room.withdraw(address(usdc));
    }

    // ── Protocol-fee governance (timelock + freeze) ────────────────────

    function test_FeeBpsDefaultsToOnePercent() public {
        assertEq(room.feeBps(), 100);
        assertEq(room.DEFAULT_FEE_BPS(), 100);
    }

    function test_ProposeAndActivateFeeBps() public {
        room.proposeFeeBps(200);
        assertEq(room.feeBps(), 100); // not yet active
        vm.warp(block.timestamp + 2 days);
        room.activateFeeBps();
        assertEq(room.feeBps(), 200);

        // A new deal now meters the fee at 2% (refresh expiry past the warp).
        expiry = block.timestamp + 1 days;
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);
        assertEq(room.getDeal(id).fee, (0.1 ether * 200) / 10000);
    }

    function test_ActivateFeeBps_RevertTooEarly() public {
        room.proposeFeeBps(200);
        vm.expectRevert(
            abi.encodeWithSelector(DiligenceRoom.FeeActivationTooEarly.selector, block.timestamp + 2 days)
        );
        room.activateFeeBps();
    }

    function test_ProposeFeeBps_RevertTooHigh() public {
        vm.expectRevert(DiligenceRoom.FeeBpsTooHigh.selector);
        room.proposeFeeBps(1001); // > MAX_FEE_BPS (1000)
    }

    function test_ProposeFeeBps_OnlyDeveloper() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.proposeFeeBps(200);
    }

    function test_ProposeFeeBps_RevertProposalExists() public {
        room.proposeFeeBps(200);
        vm.expectRevert(DiligenceRoom.FeeBpsProposalExists.selector);
        room.proposeFeeBps(300);
    }

    function test_CancelFeeBpsProposal() public {
        room.proposeFeeBps(200);
        room.cancelFeeBpsProposal();
        // Fresh proposal is now possible, and activation of the cancelled one fails.
        vm.expectRevert(DiligenceRoom.NoFeeBpsPending.selector);
        room.activateFeeBps();
        room.proposeFeeBps(300); // no ProposalExists revert
    }

    function test_FreezeFeeBps_BlocksFurtherChanges() public {
        room.freezeFeeBps();
        assertTrue(room.feeBpsFrozen());
        vm.expectRevert(DiligenceRoom.FeeBpsFrozenError.selector);
        room.proposeFeeBps(200);
    }

    function test_FeeChangeDoesNotRetroactOnEvaluatedDeal() public {
        // Evaluate a deal at the default 1% fee.
        uint256 oldDeal = _createDeal();
        _fundDeal(oldDeal);
        _submitResult(oldDeal, DiligenceRoom.ScoreBand.High, 0.1 ether);
        uint256 lockedFee = room.getDeal(oldDeal).fee;
        assertEq(lockedFee, (0.1 ether * 100) / 10000);

        // Raise the fee to 2%.
        room.proposeFeeBps(200);
        vm.warp(block.timestamp + 2 days);
        room.activateFeeBps();

        // The already-evaluated deal keeps its locked 1% fee.
        assertEq(room.getDeal(oldDeal).fee, lockedFee);
    }

    // ── Settlement conservation fuzz tests ─────────────────────────────

    function testFuzz_RejectConservation(uint256 compute) public {
        compute = bound(compute, 0, budgetCap - (budgetCap / 101) - 1);
        uint256 fee = (compute * 100) / 10000;
        vm.assume(compute + fee <= budgetCap);

        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, compute);
        vm.prank(buyer);
        room.rejectDeal(id);

        uint256 devPending = room.pendingWithdrawals(address(0), dev);
        uint256 buyerPending = room.pendingWithdrawals(address(0), buyer);
        assertEq(room.pendingWithdrawals(address(0), seller), 0);
        assertEq(devPending, compute + fee);
        assertEq(devPending + buyerPending, budgetCap);
    }

    function testFuzz_ExpireEvaluatedConservation(uint256 compute) public {
        compute = bound(compute, 0, budgetCap - (budgetCap / 101) - 1);
        uint256 fee = (compute * 100) / 10000;
        vm.assume(compute + fee <= budgetCap);

        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, compute);
        vm.warp(expiry + 1);
        room.expireDeal(id);

        uint256 devPending = room.pendingWithdrawals(address(0), dev);
        uint256 buyerPending = room.pendingWithdrawals(address(0), buyer);
        assertEq(devPending, compute + fee);
        assertEq(devPending + buyerPending, budgetCap);
    }

    function test_ExpireFundedRefundsFullBudget() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        vm.warp(expiry + 1);
        room.expireDeal(id);
        // No result submitted -> developer gets nothing, buyer gets the whole cap.
        assertEq(room.pendingWithdrawals(address(0), dev), 0);
        assertEq(room.pendingWithdrawals(address(0), buyer), budgetCap);
    }

    function testFuzz_ERC20AcceptConservation(uint256 cap, uint256 compute, uint256 payment) public {
        MockERC20 usdc = new MockERC20();
        cap = bound(cap, TOKEN_RESERVE * 4, 1_000_000_000);
        compute = bound(compute, 0, cap / 4);
        uint256 fee = (compute * 100) / 10000;
        payment = bound(payment, TOKEN_RESERVE, cap - compute - fee);

        uint256 id = _createTokenDeal(address(usdc));
        _fundTokenDeal(usdc, id, cap);
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, compute);
        vm.prank(buyer);
        room.acceptDeal(id, payment);

        uint256 total = room.pendingWithdrawals(address(usdc), seller)
            + room.pendingWithdrawals(address(usdc), dev)
            + room.pendingWithdrawals(address(usdc), buyer);
        assertEq(total, cap);
        assertEq(usdc.balanceOf(address(room)), cap);
        assertEq(room.pendingWithdrawals(address(usdc), seller), payment);
        assertEq(room.pendingWithdrawals(address(usdc), dev), compute + fee);
    }

    function testFuzz_ERC20RejectConservation(uint256 cap, uint256 compute) public {
        MockERC20 usdc = new MockERC20();
        cap = bound(cap, TOKEN_RESERVE * 4, 1_000_000_000);
        compute = bound(compute, 0, cap / 4);
        uint256 fee = (compute * 100) / 10000;

        uint256 id = _createTokenDeal(address(usdc));
        _fundTokenDeal(usdc, id, cap);
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, compute);
        vm.prank(buyer);
        room.rejectDeal(id);

        uint256 total = room.pendingWithdrawals(address(usdc), dev)
            + room.pendingWithdrawals(address(usdc), buyer);
        assertEq(room.pendingWithdrawals(address(usdc), seller), 0);
        assertEq(room.pendingWithdrawals(address(usdc), dev), compute + fee);
        assertEq(total, cap);
    }

    function testFuzz_ERC20EndToEndWithdrawalConservation(
        uint256 cap,
        uint256 compute,
        uint256 payment
    ) public {
        MockERC20 usdc = new MockERC20();
        cap = bound(cap, TOKEN_RESERVE * 4, 1_000_000_000);
        compute = bound(compute, 0, cap / 4);
        uint256 fee = (compute * 100) / 10000;
        payment = bound(payment, TOKEN_RESERVE, cap - compute - fee);

        uint256 id = _createTokenDeal(address(usdc));
        _fundTokenDeal(usdc, id, cap);
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, compute);
        vm.prank(buyer);
        room.acceptDeal(id, payment);

        // Every recipient with a nonzero payout withdraws; nothing is created,
        // stuck, or destroyed. (A zero payout reverts NothingToWithdraw, so it is
        // skipped — that recipient already holds nothing.)
        if (room.pendingWithdrawals(address(usdc), seller) > 0) {
            vm.prank(seller);
            room.withdraw(address(usdc));
        }
        if (room.pendingWithdrawals(address(usdc), dev) > 0) {
            room.withdraw(address(usdc)); // developer == this test contract
        }
        if (room.pendingWithdrawals(address(usdc), buyer) > 0) {
            vm.prank(buyer);
            room.withdraw(address(usdc));
        }

        assertEq(usdc.balanceOf(address(room)), 0);
        uint256 withdrawn = usdc.balanceOf(seller)
            + usdc.balanceOf(dev)
            + usdc.balanceOf(buyer);
        assertEq(withdrawn, cap);
    }

    // Allow receiving ETH (developer is this contract in tests)
    receive() external payable {}
}
