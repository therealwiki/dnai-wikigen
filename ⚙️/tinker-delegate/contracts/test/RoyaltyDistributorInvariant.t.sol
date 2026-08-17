// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";
import {RoyaltyDistributor} from "../src/RoyaltyDistributor.sol";

contract InvariantRoyaltyERC20 {
    mapping(address account => uint256 amount) public balanceOf;
    mapping(address owner => mapping(address spender => uint256 amount)) public allowance;

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract RoyaltyDistributorHandler is Test {
    uint256 internal constant MAX_TRACKED_RESERVATIONS = 8;
    RoyaltyDistributor internal immutable distributor;
    ExecutionPolicyAnchor internal immutable anchor;
    InvariantRoyaltyERC20 internal immutable token;
    address internal immutable settlementVerifier;
    address internal immutable qvlVerifier;
    address internal immutable ownerA;
    address internal immutable ownerB;
    uint256 internal immutable settlementSignerKey;
    uint256 internal immutable qvlSignerKey;
    bytes32 internal immutable anchorWriterRelease;

    uint256 public settlementCount;
    uint256 public totalFunded;
    uint256 public totalWithdrawn;
    uint256 public totalRefunded;
    uint256 public totalTokenFunded;
    uint256 public totalTokenWithdrawn;
    uint256 public totalTokenRefunded;
    uint256 public reservationCount;
    mapping(uint256 index => bytes32 reservationId) public reservationIds;
    mapping(uint256 index => uint8 status) public reservationStatusModel;
    mapping(uint256 index => uint64 refundAfter) public reservationDeadlines;
    mapping(uint256 index => uint256 amount) public reservationAmountA;
    mapping(uint256 index => uint256 amount) public reservationAmountB;
    mapping(uint256 index => RoyaltyDistributor.SettlementAuthorization authorization) internal
        reservationAuthorizations;

    constructor(
        RoyaltyDistributor distributor_,
        ExecutionPolicyAnchor anchor_,
        InvariantRoyaltyERC20 token_,
        uint256 settlementSignerKey_,
        uint256 qvlSignerKey_,
        address ownerA_,
        address ownerB_,
        bytes32 anchorWriterRelease_
    ) {
        distributor = distributor_;
        anchor = anchor_;
        token = token_;
        settlementSignerKey = settlementSignerKey_;
        qvlSignerKey = qvlSignerKey_;
        settlementVerifier = vm.addr(settlementSignerKey_);
        qvlVerifier = vm.addr(qvlSignerKey_);
        ownerA = ownerA_;
        ownerB = ownerB_;
        anchorWriterRelease = anchorWriterRelease_;
        token.approve(address(distributor_), type(uint256).max);
    }

    function settle(uint96 rawA, uint96 rawB) external {
        uint256 amountA = bound(uint256(rawA), 1, 5 ether);
        uint256 amountB = bound(uint256(rawB), 1, 5 ether);
        uint256 total = amountA + amountB;
        uint256 nonce = ++settlementCount;

        address[] memory owners = new address[](2);
        owners[0] = ownerA;
        owners[1] = ownerB;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amountA;
        amounts[1] = amountB;

        RoyaltyDistributor.SettlementAuthorization memory authorization;
        bytes32 salt = keccak256(abi.encode(nonce, amountA, amountB));
        authorization.settlementId = keccak256(abi.encode("invariant-settlement", salt));
        authorization.settlementNonce = nonce;
        authorization.releasePolicyCommitment = distributor.releasePolicyCommitment();
        authorization.roomCommitment = keccak256(abi.encode("invariant-room", salt));
        authorization.roomStateCommitment = keccak256(abi.encode("invariant-room-state", salt));
        authorization.queryCommitment = keccak256(abi.encode("invariant-query", salt));
        authorization.grantSetCommitment = keccak256(abi.encode("invariant-grants", salt));
        authorization.allocationCommitment = keccak256(abi.encode("invariant-allocation", salt));
        authorization.ownersAmountsHash = distributor.computeOwnerAmountsHash(owners, amounts);
        authorization.total = total;
        authorization.executionCommitment = keccak256(abi.encode("invariant-execution", salt));
        authorization.resultCommitment = keccak256(abi.encode("invariant-result", salt));
        authorization.usageCommitment = keccak256(abi.encode("invariant-usage", salt));
        authorization.attestationEvidenceHash = keccak256(abi.encode("invariant-attestation", salt));
        authorization.expiry = block.timestamp + distributor.MAX_AUTHORIZATION_LIFETIME();
        authorization.anchorResourceHash =
            distributor.collaborationResourceHash(authorization.roomCommitment, authorization.queryCommitment);
        authorization.anchorDecisionHash = distributor.settlementDecisionHash(authorization);

        (authorization.anchorSequence,) = anchor.anchorDecision(
            anchor.globalSequence(),
            anchor.globalHead(),
            authorization.anchorResourceHash,
            bytes32(0),
            authorization.anchorDecisionHash,
            anchorWriterRelease
        );
        bytes memory settlementSignature =
            _signature(settlementSignerKey, distributor.settlementAuthorizationDigest(authorization));
        bytes memory qvlSignature =
            _signature(qvlSignerKey, distributor.settlementQvlAuthorizationDigest(authorization));

        vm.deal(address(this), total);
        distributor.distributeNative{value: total}(authorization, owners, amounts, settlementSignature, qvlSignature);
        totalFunded += total;
    }

    function reserve(uint96 rawA, uint96 rawB, uint32 rawLifetime, bool tokenAsset) external {
        if (reservationCount >= MAX_TRACKED_RESERVATIONS) return;
        uint256 amountA = bound(uint256(rawA), 1, 5 ether);
        uint256 amountB = bound(uint256(rawB), 1, 5 ether);
        uint256 total = amountA + amountB;
        uint256 nonce = ++settlementCount;
        uint64 refundAfter = uint64(block.timestamp + bound(uint256(rawLifetime), 601, 1 days));

        address[] memory owners = new address[](2);
        owners[0] = ownerA;
        owners[1] = ownerB;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amountA;
        amounts[1] = amountB;
        bytes32 salt = keccak256(abi.encode("reservation", nonce, amountA, amountB));
        RoyaltyDistributor.SettlementAuthorization memory authorization;
        authorization.settlementId = keccak256(abi.encode("invariant-reservation", salt));
        authorization.settlementNonce = nonce;
        authorization.releasePolicyCommitment = distributor.releasePolicyCommitment();
        authorization.roomCommitment = keccak256(abi.encode("invariant-room", salt));
        authorization.roomStateCommitment = keccak256(abi.encode("invariant-room-state", salt));
        authorization.queryCommitment = keccak256(abi.encode("invariant-query", salt));
        authorization.grantSetCommitment = keccak256(abi.encode("invariant-grants", salt));
        authorization.allocationCommitment = keccak256(abi.encode("invariant-allocation", salt));
        authorization.ownersAmountsHash = distributor.computeOwnerAmountsHash(owners, amounts);
        authorization.asset = tokenAsset ? address(token) : address(0);
        authorization.total = total;
        authorization.executionCommitment = keccak256(abi.encode("invariant-execution", salt));
        authorization.resultCommitment = keccak256(abi.encode("invariant-result", salt));
        authorization.usageCommitment = keccak256(abi.encode("invariant-usage", salt));
        authorization.attestationEvidenceHash = keccak256(abi.encode("invariant-attestation", salt));
        authorization.anchorResourceHash =
            distributor.collaborationResourceHash(authorization.roomCommitment, authorization.queryCommitment);
        authorization.expiry = block.timestamp + distributor.MAX_AUTHORIZATION_LIFETIME();

        RoyaltyDistributor.FundingReservationRequest memory request = RoyaltyDistributor.FundingReservationRequest({
            settlementId: authorization.settlementId,
            settlementNonce: authorization.settlementNonce,
            releasePolicyCommitment: authorization.releasePolicyCommitment,
            roomCommitment: authorization.roomCommitment,
            roomStateCommitment: authorization.roomStateCommitment,
            queryCommitment: authorization.queryCommitment,
            grantSetCommitment: authorization.grantSetCommitment,
            allocationCommitment: authorization.allocationCommitment,
            ownersAmountsHash: authorization.ownersAmountsHash,
            asset: authorization.asset,
            total: authorization.total,
            executionCommitment: authorization.executionCommitment,
            refundAfter: refundAfter
        });
        bytes32 reservationId;
        if (tokenAsset) {
            token.mint(address(this), total);
            reservationId = distributor.reserveERC20(request);
            totalTokenFunded += total;
        } else {
            vm.deal(address(this), total);
            reservationId = distributor.reserveNative{value: total}(request);
            totalFunded += total;
        }
        authorization.fundingReservationId = reservationId;

        uint256 index = reservationCount++;
        reservationIds[index] = reservationId;
        reservationStatusModel[index] = 1;
        reservationDeadlines[index] = refundAfter;
        reservationAmountA[index] = amountA;
        reservationAmountB[index] = amountB;
        reservationAuthorizations[index] = authorization;
    }

    function consumeReservation(uint256 seed) external {
        if (reservationCount == 0) return;
        uint256 index = seed % reservationCount;
        if (reservationStatusModel[index] != 1 || block.timestamp >= reservationDeadlines[index]) return;
        RoyaltyDistributor.SettlementAuthorization memory authorization = reservationAuthorizations[index];
        uint256 latestExpiry = block.timestamp + distributor.MAX_AUTHORIZATION_LIFETIME();
        if (latestExpiry > reservationDeadlines[index]) latestExpiry = reservationDeadlines[index];
        authorization.expiry = latestExpiry;
        authorization.anchorDecisionHash = distributor.settlementDecisionHash(authorization);
        (authorization.anchorSequence,) = anchor.anchorDecision(
            anchor.globalSequence(),
            anchor.globalHead(),
            authorization.anchorResourceHash,
            anchor.resourceDecisionHead(authorization.anchorResourceHash),
            authorization.anchorDecisionHash,
            anchorWriterRelease
        );
        bytes memory settlementSignature =
            _signature(settlementSignerKey, distributor.settlementAuthorizationDigest(authorization));
        bytes memory qvlSignature =
            _signature(qvlSignerKey, distributor.settlementQvlAuthorizationDigest(authorization));
        address[] memory owners = new address[](2);
        owners[0] = ownerA;
        owners[1] = ownerB;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = reservationAmountA[index];
        amounts[1] = reservationAmountB[index];
        distributor.settleReserved(
            reservationIds[index], authorization, owners, amounts, settlementSignature, qvlSignature
        );
        reservationStatusModel[index] = 2;
        reservationAuthorizations[index] = authorization;
    }

    function warpAndRefundReservation(uint256 seed) external {
        if (reservationCount == 0) return;
        uint256 index = seed % reservationCount;
        if (reservationStatusModel[index] != 1) return;
        uint64 refundAfter = reservationDeadlines[index];
        if (block.timestamp < refundAfter) vm.warp(refundAfter);
        uint256 amount = reservationAuthorizations[index].total;
        distributor.refundFundingReservation(reservationIds[index]);
        reservationStatusModel[index] = 3;
        if (reservationAuthorizations[index].asset == address(token)) {
            totalTokenRefunded += amount;
        } else {
            totalRefunded += amount;
        }
    }

    function replayTerminalReservation(uint256 seed) external {
        if (reservationCount == 0) return;
        uint256 index = seed % reservationCount;
        if (reservationStatusModel[index] < 2) return;
        (bool refundOk,) = address(distributor)
            .call(abi.encodeWithSelector(RoyaltyDistributor.refundFundingReservation.selector, reservationIds[index]));
        assertFalse(refundOk);
        address[] memory owners = new address[](0);
        uint256[] memory amounts = new uint256[](0);
        (bool settleOk,) = address(distributor)
            .call(
                abi.encodeWithSelector(
                    RoyaltyDistributor.settleReserved.selector,
                    reservationIds[index],
                    reservationAuthorizations[index],
                    owners,
                    amounts,
                    bytes(""),
                    bytes("")
                )
            );
        assertFalse(settleOk);
    }

    function withdrawOwnerA() external {
        _withdraw(ownerA);
    }

    function withdrawOwnerB() external {
        _withdraw(ownerB);
    }

    function _withdraw(address ownerAccount) internal {
        uint256 amount = distributor.pending(address(0), ownerAccount);
        if (amount != 0) {
            vm.prank(ownerAccount);
            distributor.withdraw();
            totalWithdrawn += amount;
        }
        uint256 tokenAmount = distributor.pending(address(token), ownerAccount);
        if (tokenAmount != 0) {
            vm.prank(ownerAccount);
            distributor.withdraw(address(token));
            totalTokenWithdrawn += tokenAmount;
        }
    }

    function _signature(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    receive() external payable {}
}

contract RoyaltyDistributorInvariantTest is StdInvariant, Test {
    uint256 internal constant SETTLEMENT_SIGNER_KEY = 0x51A11;
    uint256 internal constant QVL_SIGNER_KEY = 0x51B0B;
    bytes32 internal constant ANCHOR_WRITER_RELEASE = keccak256("invariant-anchor-release");

    RoyaltyDistributor internal distributor;
    ExecutionPolicyAnchor internal anchor;
    InvariantRoyaltyERC20 internal token;
    RoyaltyDistributorHandler internal handler;
    address internal ownerA = address(0x1001);
    address internal ownerB = address(0x1002);

    function setUp() public {
        vm.warp(100 days);
        anchor = new ExecutionPolicyAnchor(
            address(this), keccak256("invariant-deployment"), keccak256("invariant-reviewer-genesis")
        );
        distributor = new RoyaltyDistributor(address(this));
        token = new InvariantRoyaltyERC20();
        handler = new RoyaltyDistributorHandler(
            distributor, anchor, token, SETTLEMENT_SIGNER_KEY, QVL_SIGNER_KEY, ownerA, ownerB, ANCHOR_WRITER_RELEASE
        );

        anchor.proposeWriter(address(handler), ANCHOR_WRITER_RELEASE);
        vm.warp(anchor.pendingWriterActivatesAt());
        anchor.activateWriter();
        anchor.freezeWriterRotations();
        anchor.setPaused(false);

        distributor.proposeAuthorityBinding(
            vm.addr(SETTLEMENT_SIGNER_KEY), vm.addr(QVL_SIGNER_KEY), address(anchor), ANCHOR_WRITER_RELEASE
        );
        vm.warp(distributor.pendingAuthorityActivatesAt());
        distributor.activateAuthorityProposal();
        distributor.setPaused(false);
        handler.reserve(1 ether, 2 ether, 900, false);
        handler.reserve(3 ether, 4 ether, 900, true);
        targetContract(address(handler));
    }

    function invariant_NativeBalanceAlwaysEqualsOwnerLiabilities() public view {
        uint256 liabilities = distributor.pending(address(0), ownerA) + distributor.pending(address(0), ownerB)
            + distributor.totalReserved(address(0));
        assertEq(address(distributor).balance, liabilities);
        assertEq(
            distributor.totalPending(address(0)),
            distributor.pending(address(0), ownerA) + distributor.pending(address(0), ownerB)
        );
        assertGe(
            address(distributor).balance, distributor.totalReserved(address(0)) + distributor.totalPending(address(0))
        );
    }

    function invariant_FundedValueEqualsWithdrawnPlusCustodiedValue() public view {
        assertEq(
            handler.totalFunded(), handler.totalWithdrawn() + handler.totalRefunded() + address(distributor).balance
        );
        assertEq(
            handler.totalTokenFunded(),
            handler.totalTokenWithdrawn() + handler.totalTokenRefunded() + token.balanceOf(address(distributor))
        );
    }

    function invariant_TokenBalanceAlwaysEqualsOwnerLiabilities() public view {
        uint256 liabilities = distributor.pending(address(token), ownerA) + distributor.pending(address(token), ownerB)
            + distributor.totalReserved(address(token));
        assertEq(token.balanceOf(address(distributor)), liabilities);
        assertEq(
            distributor.totalPending(address(token)),
            distributor.pending(address(token), ownerA) + distributor.pending(address(token), ownerB)
        );
        assertGe(
            token.balanceOf(address(distributor)),
            distributor.totalReserved(address(token)) + distributor.totalPending(address(token))
        );
    }

    function invariant_ReservationsAreOneWayAndGetterActiveIsExact() public view {
        for (uint256 index = 0; index < handler.reservationCount(); index++) {
            bytes32 reservationId = handler.reservationIds(index);
            (RoyaltyDistributor.FundingReservation memory stored, bool active) =
                distributor.fundingReservationState(reservationId);
            uint8 expectedStatus = handler.reservationStatusModel(index);
            assertEq(uint256(stored.status), expectedStatus);
            assertEq(
                active,
                expectedStatus == uint8(RoyaltyDistributor.FundingReservationStatus.Active)
                    && block.timestamp < handler.reservationDeadlines(index)
            );
            RoyaltyDistributor.FundingReservationView memory viewState =
                distributor.collaborationFundingReservation(reservationId);
            assertEq(viewState.active, active);
            assertEq(viewState.consumed, expectedStatus == uint8(RoyaltyDistributor.FundingReservationStatus.Consumed));
            assertEq(
                viewState.depositedAmount,
                expectedStatus == uint8(RoyaltyDistributor.FundingReservationStatus.Active) ? stored.total : 0
            );
            RoyaltyDistributor.FundingReservationSettlementView memory settlementState =
                distributor.fundingReservationSettlementState(reservationId);
            bool consumed = expectedStatus == uint8(RoyaltyDistributor.FundingReservationStatus.Consumed);
            assertEq(settlementState.consumed, consumed);
            assertEq(settlementState.settlementProcessed, consumed);
            assertEq(settlementState.nonceProcessed, consumed);
            assertEq(settlementState.settlementId, stored.settlementId);
            assertEq(settlementState.settlementNonce, stored.settlementNonce);
            assertEq(settlementState.asset, stored.asset);
            assertEq(settlementState.total, stored.total);
            assertEq(settlementState.ownerAmountsHash, stored.ownersAmountsHash);
        }
    }

    function invariant_ReleaseAuthorityRemainsDistinctAndBound() public view {
        assertFalse(distributor.paused());
        assertNotEq(distributor.settlementVerifier(), distributor.qvlVerifier());
        assertEq(distributor.executionPolicyAnchor(), address(anchor));
        assertEq(distributor.anchorWriterReleaseCommitment(), ANCHOR_WRITER_RELEASE);
        assertNotEq(distributor.releasePolicyCommitment(), bytes32(0));
    }
}
