// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";
import {RoyaltyDistributor} from "../src/RoyaltyDistributor.sol";

contract MockRoyaltyERC20 {
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

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
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

/// @dev Funds correctly, then claims successful outbound transfers without
///      moving balances. Exact egress checks must preserve the owner claim.
contract RoyaltyOutboundPhantomERC20 is MockRoyaltyERC20 {
    function transfer(address, uint256) external pure override returns (bool) {
        return true;
    }
}

/// @dev Attempts to enter a withdrawal from transferFrom. The distributor's
///      global reentrancy lock must reject the callback before any accounting
///      can be observed or changed, while the honest transfer may still finish.
contract RoyaltyCallbackERC20 is MockRoyaltyERC20 {
    RoyaltyDistributor internal immutable distributor;
    bool public callbackBlocked;

    constructor(RoyaltyDistributor distributor_) {
        distributor = distributor_;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        (bool ok,) = address(distributor).call(abi.encodeWithSignature("withdraw(address)", address(this)));
        callbackBlocked = !ok;
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev Burns one unit on ingress so exact reservation funding must revert.
contract RoyaltyFeeOnTransferERC20 is MockRoyaltyERC20 {
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - 1;
        return true;
    }
}

/// @dev Attempts a second refund from the native refund callback. The outer
///      reservation transition and global lock must prevent a double refund.
contract ReentrantReservationSponsor {
    RoyaltyDistributor internal immutable distributor;
    bytes32 public reservationId;
    uint256 public received;
    bool public callbackBlocked;

    constructor(RoyaltyDistributor distributor_) {
        distributor = distributor_;
    }

    function reserve(RoyaltyDistributor.FundingReservationRequest calldata request) external payable {
        reservationId = distributor.reserveNative{value: msg.value}(request);
    }

    function refund() external {
        distributor.refundFundingReservation(reservationId);
    }

    receive() external payable {
        received += msg.value;
        (bool ok,) = address(distributor)
            .call(abi.encodeWithSelector(RoyaltyDistributor.refundFundingReservation.selector, reservationId));
        callbackBlocked = !ok;
    }
}

contract MockRoyalty1271Signer {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    mapping(bytes32 => bool) public approvedDigest;

    function approve(bytes32 digest) external {
        approvedDigest[digest] = true;
    }

    function isValidSignature(bytes32 digest, bytes calldata) external view returns (bytes4) {
        return approvedDigest[digest] ? MAGIC_VALUE : bytes4(0xffffffff);
    }
}

/// @dev ERC-1271 validation runs through STATICCALL. Even though this signer is
///      an active emergency authority, its attempted pause must fail in the
///      static context and cannot mutate distributor state.
contract RoyaltyCallback1271Signer {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    RoyaltyDistributor internal immutable distributor;
    mapping(bytes32 => bool) public approvedDigest;

    constructor(RoyaltyDistributor distributor_) {
        distributor = distributor_;
    }

    function approve(bytes32 digest) external {
        approvedDigest[digest] = true;
    }

    function isValidSignature(bytes32 digest, bytes calldata) external view returns (bytes4) {
        (bool callbackSucceeded,) = address(distributor).staticcall{gas: 20_000}(
            abi.encodeWithSelector(RoyaltyDistributor.setPaused.selector, true)
        );
        require(!callbackSucceeded, "static signature callback mutated state");
        return approvedDigest[digest] ? MAGIC_VALUE : bytes4(0xffffffff);
    }
}

/// @dev Adversarial anchor double used only to prove that proposal-time reads
///      are repeated at activation; its reported release may drift in between.
contract MutableRoyaltyAnchor {
    address public writer;
    bytes32 public writerReleaseCommitment;
    bool public writerRotationsFrozen = true;
    bool public paused;
    mapping(bytes32 => bytes32) public resourceDecisionHead;
    mapping(bytes32 => uint256) public resourceSequence;
    mapping(bytes32 => uint256) public decisionSequence;

    constructor(address writer_, bytes32 release_) {
        writer = writer_;
        writerReleaseCommitment = release_;
    }

    function setRelease(bytes32 release_) external {
        writerReleaseCommitment = release_;
    }
}

contract ReentrantRoyaltyClaimer {
    RoyaltyDistributor internal immutable distributor;
    bool internal entered;
    uint256 public received;

    constructor(RoyaltyDistributor distributor_) {
        distributor = distributor_;
    }

    function claim() external {
        distributor.withdraw();
    }

    receive() external payable {
        received += msg.value;
        if (!entered) {
            entered = true;
            try distributor.withdraw() {} catch {}
        }
    }
}

contract RoyaltyDistributorTest is Test {
    uint256 internal constant SETTLEMENT_SIGNER_KEY = 0xA11CE;
    uint256 internal constant QVL_SIGNER_KEY = 0xB0B;
    uint256 internal constant ANCHOR_WRITER_KEY = 0xC0FFEE;
    bytes32 internal constant ANCHOR_WRITER_RELEASE = keccak256("anchor-writer-release");

    RoyaltyDistributor internal distributor;
    ExecutionPolicyAnchor internal anchor;

    address internal settlementVerifier;
    address internal qvlVerifier;
    address internal anchorWriter;
    address internal payer = makeAddr("payer");
    address internal ownerA = address(0xA11CE);
    address internal ownerB = address(0xB0B01);

    function setUp() public {
        vm.warp(30 days);
        settlementVerifier = vm.addr(SETTLEMENT_SIGNER_KEY);
        qvlVerifier = vm.addr(QVL_SIGNER_KEY);
        anchorWriter = vm.addr(ANCHOR_WRITER_KEY);

        anchor = new ExecutionPolicyAnchor(
            address(this), keccak256("deployment-intent"), keccak256("reviewer-genesis-acceptance")
        );
        anchor.proposeWriter(anchorWriter, ANCHOR_WRITER_RELEASE);
        vm.warp(block.timestamp + anchor.WRITER_ROTATION_DELAY());
        anchor.activateWriter();
        anchor.freezeWriterRotations();
        anchor.setPaused(false);

        distributor = new RoyaltyDistributor(address(this));
        distributor.proposeAuthorityBinding(settlementVerifier, qvlVerifier, address(anchor), ANCHOR_WRITER_RELEASE);
        vm.warp(block.timestamp + distributor.AUTHORITY_TIMELOCK());
        distributor.activateAuthorityProposal();
        distributor.setPaused(false);
        vm.deal(payer, 100 ether);
    }

    function _owners() internal view returns (address[] memory owners) {
        owners = new address[](2);
        owners[0] = ownerA;
        owners[1] = ownerB;
    }

    function _sortedOwners(address a, address b) internal pure returns (address[] memory owners) {
        owners = new address[](2);
        if (a < b) {
            owners[0] = a;
            owners[1] = b;
        } else {
            owners[0] = b;
            owners[1] = a;
        }
    }

    function _amounts(uint256 a, uint256 b) internal pure returns (uint256[] memory amounts) {
        amounts = new uint256[](2);
        amounts[0] = a;
        amounts[1] = b;
    }

    function _authorization(
        address asset,
        uint256 total,
        uint256 nonce,
        bytes32 salt,
        address[] memory owners,
        uint256[] memory amounts
    ) internal returns (RoyaltyDistributor.SettlementAuthorization memory authorization) {
        authorization.settlementId = keccak256(abi.encode("settlement", salt));
        authorization.settlementNonce = nonce;
        authorization.releasePolicyCommitment = distributor.releasePolicyCommitment();
        authorization.roomCommitment = keccak256(abi.encode("room", salt));
        authorization.roomStateCommitment = keccak256(abi.encode("room-state", salt));
        authorization.queryCommitment = keccak256(abi.encode("query", salt));
        authorization.grantSetCommitment = keccak256(abi.encode("grant-set", salt));
        authorization.allocationCommitment = keccak256(abi.encode("allocation", salt));
        authorization.ownersAmountsHash = distributor.computeOwnerAmountsHash(owners, amounts);
        authorization.asset = asset;
        authorization.total = total;
        authorization.executionCommitment = keccak256(abi.encode("execution", salt));
        authorization.resultCommitment = keccak256(abi.encode("result", salt));
        authorization.usageCommitment = keccak256(abi.encode("usage", salt));
        authorization.attestationEvidenceHash = keccak256(abi.encode("attestation", salt));
        authorization.expiry = block.timestamp + distributor.MAX_AUTHORIZATION_LIFETIME();
        authorization.anchorResourceHash =
            distributor.collaborationResourceHash(authorization.roomCommitment, authorization.queryCommitment);
        authorization.anchorDecisionHash = distributor.settlementDecisionHash(authorization);
        authorization.anchorSequence =
            _anchorDecision(authorization.anchorResourceHash, authorization.anchorDecisionHash);
    }

    function _anchorDecision(bytes32 resourceHash, bytes32 decisionHash) internal returns (uint256 sequence) {
        uint256 expectedSequence = anchor.globalSequence();
        bytes32 expectedGlobalHead = anchor.globalHead();
        bytes32 expectedResourceHead = anchor.resourceDecisionHead(resourceHash);
        vm.prank(anchorWriter);
        (sequence,) = anchor.anchorDecision(
            expectedSequence,
            expectedGlobalHead,
            resourceHash,
            expectedResourceHead,
            decisionHash,
            ANCHOR_WRITER_RELEASE
        );
    }

    function _sign(RoyaltyDistributor.SettlementAuthorization memory authorization)
        internal
        returns (bytes memory settlementSignature, bytes memory qvlSignature)
    {
        settlementSignature =
            _signature(SETTLEMENT_SIGNER_KEY, distributor.settlementAuthorizationDigest(authorization));
        qvlSignature = _signature(QVL_SIGNER_KEY, distributor.settlementQvlAuthorizationDigest(authorization));
    }

    function _signature(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _repeatByte(uint8 value) internal pure returns (bytes32) {
        return bytes32(uint256(value) * (type(uint256).max / type(uint8).max));
    }

    function _prepareNative(uint256 a, uint256 b, uint256 nonce, bytes32 salt)
        internal
        returns (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        )
    {
        owners = _owners();
        amounts = _amounts(a, b);
        authorization = _authorization(address(0), a + b, nonce, salt, owners, amounts);
        (settlementSignature, qvlSignature) = _sign(authorization);
    }

    function _reservationRequest(RoyaltyDistributor.SettlementAuthorization memory authorization, uint64 refundAfter)
        internal
        pure
        returns (RoyaltyDistributor.FundingReservationRequest memory request)
    {
        request = RoyaltyDistributor.FundingReservationRequest({
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
    }

    function _bindReservationAndSign(
        RoyaltyDistributor.SettlementAuthorization memory authorization,
        bytes32 reservationId
    )
        internal
        returns (
            RoyaltyDistributor.SettlementAuthorization memory bound,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        )
    {
        bound = authorization;
        bound.fundingReservationId = reservationId;
        bound.anchorDecisionHash = distributor.settlementDecisionHash(bound);
        bound.anchorSequence = _anchorDecision(bound.anchorResourceHash, bound.anchorDecisionHash);
        (settlementSignature, qvlSignature) = _sign(bound);
    }

    // -- Fresh release and governance --------------------------------

    function test_FreshDistributorIsOwnedPausedAndFailClosed() public {
        RoyaltyDistributor fresh = new RoyaltyDistributor(address(this));
        assertEq(fresh.owner(), address(this));
        assertTrue(fresh.paused());
        assertEq(fresh.settlementVerifier(), address(0));
        assertEq(fresh.qvlVerifier(), address(0));
        assertEq(fresh.executionPolicyAnchor(), address(0));
        assertEq(fresh.releasePolicyCommitment(), bytes32(0));
        assertEq(fresh.authorityNonce(), 0);
    }

    function test_AuthorityProposalIsTimelockedAndDerivedOnchain() public {
        RoyaltyDistributor fresh = new RoyaltyDistributor(address(this));
        fresh.proposeAuthorityBinding(settlementVerifier, qvlVerifier, address(anchor), ANCHOR_WRITER_RELEASE);

        assertEq(fresh.pendingSettlementVerifier(), settlementVerifier);
        assertEq(fresh.pendingQvlVerifier(), qvlVerifier);
        assertEq(fresh.pendingExecutionPolicyAnchor(), address(anchor));
        assertEq(fresh.pendingAuthorityNonce(), 1);
        assertEq(
            fresh.pendingReleasePolicyCommitment(),
            fresh.computeReleasePolicyCommitment(
                1, settlementVerifier, qvlVerifier, address(anchor), ANCHOR_WRITER_RELEASE
            )
        );
        vm.expectRevert(
            abi.encodeWithSelector(RoyaltyDistributor.TimelockNotElapsed.selector, fresh.pendingAuthorityActivatesAt())
        );
        fresh.activateAuthorityProposal();

        vm.warp(fresh.pendingAuthorityActivatesAt());
        fresh.activateAuthorityProposal();
        assertEq(fresh.authorityNonce(), 1);
        assertTrue(fresh.settlementVerifierEverConfigured(settlementVerifier));
        assertTrue(fresh.qvlVerifierEverConfigured(qvlVerifier));
        assertTrue(fresh.paused());
    }

    function test_CanCancelAuthorityProposal() public {
        uint256 replacementKey = 0xD00D;
        distributor.proposeAuthorityBinding(
            vm.addr(replacementKey), makeAddr("replacement-qvl"), address(anchor), ANCHOR_WRITER_RELEASE
        );
        distributor.cancelAuthorityProposal();
        assertEq(distributor.pendingAuthorityActivatesAt(), 0);
        assertEq(distributor.pendingAuthorityNonce(), 0);
        assertFalse(distributor.pendingAuthorityRevocation());
    }

    function test_RejectsSameSignerAndUnfrozenAnchor() public {
        RoyaltyDistributor fresh = new RoyaltyDistributor(address(this));
        vm.expectRevert(RoyaltyDistributor.RoleConflict.selector);
        fresh.proposeAuthorityBinding(settlementVerifier, settlementVerifier, address(anchor), ANCHOR_WRITER_RELEASE);

        ExecutionPolicyAnchor unfrozen =
            new ExecutionPolicyAnchor(address(this), keccak256("new-deployment"), keccak256("new-reviewers"));
        vm.expectRevert(RoyaltyDistributor.InvalidAnchor.selector);
        fresh.proposeAuthorityBinding(settlementVerifier, qvlVerifier, address(unfrozen), ANCHOR_WRITER_RELEASE);
    }

    function test_DistributorCannotBeItsOwnAnchorWriter() public {
        RoyaltyDistributor fresh = new RoyaltyDistributor(address(this));
        bytes32 release = keccak256("self-anchor-writer-release");
        ExecutionPolicyAnchor selfWriterAnchor = new ExecutionPolicyAnchor(
            address(this), keccak256("self-writer-deployment"), keccak256("self-writer-reviewers")
        );
        selfWriterAnchor.proposeWriter(address(fresh), release);
        vm.warp(block.timestamp + selfWriterAnchor.WRITER_ROTATION_DELAY());
        selfWriterAnchor.activateWriter();
        selfWriterAnchor.freezeWriterRotations();
        selfWriterAnchor.setPaused(false);

        vm.expectRevert(RoyaltyDistributor.RoleConflict.selector);
        fresh.proposeAuthorityBinding(settlementVerifier, qvlVerifier, address(selfWriterAnchor), release);
    }

    function test_HistoricalSignerRolesCannotBeSwapped() public {
        distributor.proposeAuthorityBinding(
            makeAddr("replacement-settlement"), makeAddr("replacement-qvl"), address(anchor), ANCHOR_WRITER_RELEASE
        );
        vm.warp(distributor.pendingAuthorityActivatesAt());
        distributor.activateAuthorityProposal();

        vm.expectRevert(RoyaltyDistributor.RoleConflict.selector);
        distributor.proposeAuthorityBinding(qvlVerifier, settlementVerifier, address(anchor), ANCHOR_WRITER_RELEASE);
    }

    function test_HistoricalAnchorWriterCannotBecomeSettlementOrOwnerAuthority() public {
        assertTrue(distributor.anchorWriterEverConfigured(anchorWriter));

        address replacementWriter = makeAddr("replacement-anchor-writer");
        bytes32 replacementRelease = keccak256("replacement-anchor-release");
        ExecutionPolicyAnchor replacementAnchor = new ExecutionPolicyAnchor(
            address(this), keccak256("replacement-deployment"), keccak256("replacement-reviewers")
        );
        replacementAnchor.proposeWriter(replacementWriter, replacementRelease);
        vm.warp(block.timestamp + replacementAnchor.WRITER_ROTATION_DELAY());
        replacementAnchor.activateWriter();
        replacementAnchor.freezeWriterRotations();
        replacementAnchor.setPaused(false);

        vm.expectRevert(RoyaltyDistributor.RoleConflict.selector);
        distributor.proposeAuthorityBinding(
            anchorWriter, makeAddr("new-qvl-after-writer"), address(replacementAnchor), replacementRelease
        );

        vm.expectRevert(RoyaltyDistributor.RoleConflict.selector);
        distributor.transferOwnership(anchorWriter);
    }

    function test_HistoricalVerifierCannotBecomeAnchorWriter() public {
        bytes32 replacementRelease = keccak256("historical-verifier-anchor-release");
        ExecutionPolicyAnchor replacementAnchor = new ExecutionPolicyAnchor(
            address(this), keccak256("historical-verifier-deployment"), keccak256("historical-verifier-reviewers")
        );
        replacementAnchor.proposeWriter(settlementVerifier, replacementRelease);
        vm.warp(block.timestamp + replacementAnchor.WRITER_ROTATION_DELAY());
        replacementAnchor.activateWriter();
        replacementAnchor.freezeWriterRotations();
        replacementAnchor.setPaused(false);

        vm.expectRevert(RoyaltyDistributor.RoleConflict.selector);
        distributor.proposeAuthorityBinding(
            makeAddr("new-settlement-for-bad-anchor"),
            makeAddr("new-qvl-for-bad-anchor"),
            address(replacementAnchor),
            replacementRelease
        );
    }

    function test_EmergencySignerCanPauseButOnlyOwnerCanResume() public {
        vm.prank(settlementVerifier);
        distributor.setPaused(true);
        assertTrue(distributor.paused());

        vm.prank(settlementVerifier);
        vm.expectRevert(RoyaltyDistributor.NotOwner.selector);
        distributor.setPaused(false);
        distributor.setPaused(false);
        assertFalse(distributor.paused());
    }

    function test_AnchorEmergencyPauseBlocksNewSettlement() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 22, keccak256("anchor-paused"));
        vm.prank(anchorWriter);
        anchor.setPaused(true);

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.InvalidAnchor.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_AnchorPauseBetweenProposalAndActivationFailsClosed() public {
        RoyaltyDistributor fresh = new RoyaltyDistributor(address(this));
        fresh.proposeAuthorityBinding(settlementVerifier, qvlVerifier, address(anchor), ANCHOR_WRITER_RELEASE);
        vm.prank(anchorWriter);
        anchor.setPaused(true);
        vm.warp(fresh.pendingAuthorityActivatesAt());

        vm.expectRevert(RoyaltyDistributor.InvalidAnchor.selector);
        fresh.activateAuthorityProposal();
    }

    function test_AnchorReleaseDriftBetweenProposalAndActivationFailsClosed() public {
        RoyaltyDistributor fresh = new RoyaltyDistributor(address(this));
        address mutableWriter = makeAddr("mutable-anchor-writer");
        bytes32 mutableRelease = keccak256("mutable-anchor-release");
        MutableRoyaltyAnchor mutableAnchor = new MutableRoyaltyAnchor(mutableWriter, mutableRelease);
        fresh.proposeAuthorityBinding(settlementVerifier, qvlVerifier, address(mutableAnchor), mutableRelease);
        mutableAnchor.setRelease(keccak256("drifted-release"));
        vm.warp(fresh.pendingAuthorityActivatesAt());

        vm.expectRevert(RoyaltyDistributor.AnchorReleaseMismatch.selector);
        fresh.activateAuthorityProposal();
    }

    function test_TimelockedRevocationClearsAuthorityAndPauses() public {
        distributor.proposeAuthorityRevocation();
        assertTrue(distributor.pendingAuthorityRevocation());
        vm.expectRevert(
            abi.encodeWithSelector(
                RoyaltyDistributor.TimelockNotElapsed.selector, distributor.pendingAuthorityActivatesAt()
            )
        );
        distributor.activateAuthorityProposal();

        vm.warp(distributor.pendingAuthorityActivatesAt());
        distributor.activateAuthorityProposal();
        assertTrue(distributor.paused());
        assertEq(distributor.settlementVerifier(), address(0));
        assertEq(distributor.qvlVerifier(), address(0));
        assertEq(distributor.executionPolicyAnchor(), address(0));
        assertEq(distributor.releasePolicyCommitment(), bytes32(0));
        assertEq(distributor.authorityNonce(), 2);
    }

    function test_TwoStepOwnershipTransferRejectsVerifierRoles() public {
        vm.expectRevert(RoyaltyDistributor.RoleConflict.selector);
        distributor.transferOwnership(settlementVerifier);

        address nextOwner = makeAddr("next-owner");
        distributor.transferOwnership(nextOwner);
        vm.prank(nextOwner);
        distributor.acceptOwnership();
        assertEq(distributor.owner(), nextOwner);
        assertEq(distributor.pendingOwner(), address(0));
    }

    // -- Native settlement -------------------------------------------

    function test_DistributeNativeCreditsExactAuthorizedOwners() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.7 ether, 0.3 ether, 1, keccak256("native-1"));

        vm.prank(payer);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);

        assertEq(distributor.pending(address(0), ownerA), 0.7 ether);
        assertEq(distributor.pending(address(0), ownerB), 0.3 ether);
        assertEq(address(distributor).balance, 1 ether);
        assertTrue(distributor.processedSettlements(authorization.settlementId));
        assertTrue(distributor.processedSettlementNonces(1));
    }

    function test_AnyFunderCanExecuteButCannotChangeEntitlement() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 2, keccak256("sponsored"));
        address sponsor = makeAddr("sponsor");
        vm.deal(sponsor, 1 ether);

        vm.prank(sponsor);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
        assertEq(distributor.pending(address(0), ownerA), 0.6 ether);
        assertEq(distributor.pending(address(0), ownerB), 0.4 ether);
    }

    function test_GlobalSettlementIdReplayCannotBeChangedByCaller() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 3, keccak256("global-replay"));
        vm.prank(payer);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);

        address anotherFunder = makeAddr("another-funder");
        vm.deal(anotherFunder, 1 ether);
        vm.prank(anotherFunder);
        vm.expectRevert(RoyaltyDistributor.SettlementAlreadyProcessed.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_GlobalNonceCannotAuthorizeDifferentSettlementId() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory first,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory firstSettlementSignature,
            bytes memory firstQvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 4, keccak256("nonce-a"));
        vm.prank(payer);
        distributor.distributeNative{value: 1 ether}(
            first, owners, amounts, firstSettlementSignature, firstQvlSignature
        );

        RoyaltyDistributor.SettlementAuthorization memory second =
            _authorization(address(0), 1 ether, 4, keccak256("nonce-b"), owners, amounts);
        (bytes memory secondSettlementSignature, bytes memory secondQvlSignature) = _sign(second);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.SettlementNonceAlreadyProcessed.selector);
        distributor.distributeNative{value: 1 ether}(
            second, owners, amounts, secondSettlementSignature, secondQvlSignature
        );
    }

    function test_RejectsCallerSuppliedOwnerMutation() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 5, keccak256("owner-mutation"));
        owners[0] = makeAddr("attacker");

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.OwnersAmountsMismatch.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_RejectsInvalidSettlementAndQvlSignatures() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 6, keccak256("bad-signatures"));

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.InvalidSettlementSignature.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, qvlSignature, qvlSignature);

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.InvalidQvlSignature.selector);
        distributor.distributeNative{value: 1 ether}(
            authorization, owners, amounts, settlementSignature, settlementSignature
        );
    }

    function test_RejectsExpiredAuthorization() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 7, keccak256("expired"));
        vm.warp(authorization.expiry + 1);

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.SettlementExpired.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_RejectsAuthorizationBeyondMaximumLifetime() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.6 ether, 0.4 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 28, keccak256("excessive-lifetime"), owners, amounts);
        authorization.expiry = block.timestamp + distributor.MAX_AUTHORIZATION_LIFETIME() + 1;
        authorization.anchorDecisionHash = distributor.settlementDecisionHash(authorization);
        authorization.anchorSequence =
            _anchorDecision(authorization.anchorResourceHash, authorization.anchorDecisionHash);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.AuthorizationLifetimeTooLong.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_SupersededAnchorDecisionFailsClosed() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 8, keccak256("superseded"));

        _anchorDecision(authorization.anchorResourceHash, keccak256("new-policy-decision"));
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.AnchorDecisionMismatch.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_ReleaseRotationInvalidatesEarlierAuthorization() public {
        bytes32 oldReleasePolicy = distributor.releasePolicyCommitment();

        distributor.proposeAuthorityBinding(
            makeAddr("new-settlement"), makeAddr("new-qvl"), address(anchor), ANCHOR_WRITER_RELEASE
        );
        vm.warp(distributor.pendingAuthorityActivatesAt());
        distributor.activateAuthorityProposal();

        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.6 ether, 0.4 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 9, keccak256("before-rotation"), owners, amounts);
        authorization.releasePolicyCommitment = oldReleasePolicy;
        authorization.anchorDecisionHash = distributor.settlementDecisionHash(authorization);
        authorization.anchorSequence =
            _anchorDecision(authorization.anchorResourceHash, authorization.anchorDecisionHash);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ReleasePolicyMismatch.selector);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_RejectsUnsortedRecipients() public {
        address[] memory unsorted = new address[](2);
        unsorted[0] = ownerB;
        unsorted[1] = ownerA;
        uint256[] memory twoAmounts = _amounts(0.5 ether, 0.5 ether);
        RoyaltyDistributor.SettlementAuthorization memory auth =
            _authorization(address(0), 1 ether, 10, keccak256("unsorted"), unsorted, twoAmounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(auth);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.OwnersNotStrictlySorted.selector);
        distributor.distributeNative{value: 1 ether}(auth, unsorted, twoAmounts, settlementSignature, qvlSignature);
    }

    function test_RejectsDuplicateRecipients() public {
        uint256[] memory twoAmounts = _amounts(0.5 ether, 0.5 ether);
        address[] memory duplicate = new address[](2);
        duplicate[0] = ownerA;
        duplicate[1] = ownerA;
        RoyaltyDistributor.SettlementAuthorization memory auth =
            _authorization(address(0), 1 ether, 11, keccak256("duplicate"), duplicate, twoAmounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(auth);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.OwnersNotStrictlySorted.selector);
        distributor.distributeNative{value: 1 ether}(auth, duplicate, twoAmounts, settlementSignature, qvlSignature);
    }

    function test_RejectsOversizedRecipientSet() public {
        address[] memory manyOwners = new address[](17);
        uint256[] memory manyAmounts = new uint256[](17);
        for (uint256 i = 0; i < 17; i++) {
            manyOwners[i] = address(uint160(i + 1));
            manyAmounts[i] = 1;
        }
        RoyaltyDistributor.SettlementAuthorization memory auth =
            _authorization(address(0), 17, 12, keccak256("many"), manyOwners, manyAmounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(auth);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.TooManyRecipients.selector);
        distributor.distributeNative{value: 17}(auth, manyOwners, manyAmounts, settlementSignature, qvlSignature);
    }

    function test_RejectsEmptyRecipientSet() public {
        address[] memory owners = new address[](0);
        uint256[] memory amounts = new uint256[](0);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1, 23, keccak256("empty"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.EmptyDistribution.selector);
        distributor.distributeNative{value: 1}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_RejectsZeroOwnerAndZeroAmount() public {
        address[] memory owners = new address[](2);
        owners[0] = address(0);
        owners[1] = ownerB;
        uint256[] memory amounts = _amounts(1, 1);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 2, 24, keccak256("zero-owner"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ZeroOwner.selector);
        distributor.distributeNative{value: 2}(authorization, owners, amounts, settlementSignature, qvlSignature);

        owners = _owners();
        amounts = _amounts(1, 0);
        authorization = _authorization(address(0), 1, 25, keccak256("zero-amount"), owners, amounts);
        (settlementSignature, qvlSignature) = _sign(authorization);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ZeroAmount.selector);
        distributor.distributeNative{value: 1}(authorization, owners, amounts, settlementSignature, qvlSignature);
    }

    function test_OwnerAmountsHashUsesEip712DynamicArrayEncoding() public view {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        bytes32 ownersHash =
            keccak256(abi.encodePacked(bytes32(uint256(uint160(ownerA))), bytes32(uint256(uint160(ownerB)))));
        bytes32 amountsHash = keccak256(abi.encodePacked(bytes32(uint256(700_000)), bytes32(uint256(300_000))));
        bytes32 expected = keccak256(abi.encode(distributor.OWNER_AMOUNTS_TYPEHASH(), ownersHash, amountsHash));
        assertEq(distributor.computeOwnerAmountsHash(owners, amounts), expected);
    }

    function test_Eip712DigestBindsChainAndDistributor() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(1, 1);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 2, 26, keccak256("domain"), owners, amounts);
        bytes32 originalDigest = distributor.settlementAuthorizationDigest(authorization);
        RoyaltyDistributor otherDistributor = new RoyaltyDistributor(address(this));
        assertNotEq(originalDigest, otherDistributor.settlementAuthorizationDigest(authorization));

        vm.chainId(block.chainid + 1);
        assertNotEq(originalDigest, distributor.settlementAuthorizationDigest(authorization));
    }

    function test_V3Eip712KnownAnswerMatchesOffchainAuthorizationCore() public {
        vm.chainId(84_532);
        address targetAddress = address(0x5555555555555555555555555555555555555555);
        vm.etch(targetAddress, address(distributor).code);
        RoyaltyDistributor target = RoyaltyDistributor(payable(targetAddress));
        RoyaltyDistributor.SettlementAuthorization memory authorization;
        authorization.settlementId = _repeatByte(0x01);
        authorization.settlementNonce = 7;
        authorization.fundingReservationId = _repeatByte(0x0f);
        authorization.releasePolicyCommitment = _repeatByte(0x02);
        authorization.roomCommitment = _repeatByte(0x03);
        authorization.roomStateCommitment = _repeatByte(0x04);
        authorization.queryCommitment = _repeatByte(0x05);
        authorization.grantSetCommitment = _repeatByte(0x06);
        authorization.allocationCommitment = _repeatByte(0x07);
        authorization.ownersAmountsHash = _repeatByte(0x08);
        authorization.asset = address(0x7777777777777777777777777777777777777777);
        authorization.total = 123_456_789;
        authorization.executionCommitment = _repeatByte(0x09);
        authorization.resultCommitment = _repeatByte(0x0a);
        authorization.usageCommitment = _repeatByte(0x0b);
        authorization.attestationEvidenceHash = _repeatByte(0x0c);
        authorization.anchorResourceHash = _repeatByte(0x0d);
        authorization.anchorDecisionHash = _repeatByte(0x0e);
        authorization.anchorSequence = 11;
        authorization.expiry = 1_800_000_060;

        assertEq(
            target.settlementAuthorizationDigest(authorization),
            0x1f6a8677f6a1260071142b5485d2e41bcd7bad78a96b3990728f223c993523b8
        );
        assertEq(
            target.settlementQvlAuthorizationDigest(authorization),
            0x872ab0d5ca653512b5fe9eed6da617e0f9c9a46691027c034bf18a134b27df2d
        );
    }

    function test_V3FundingReservationIdKnownAnswerMatchesOffchainEncoders() public {
        vm.chainId(84_532);
        address targetAddress = address(0x5555555555555555555555555555555555555555);
        address sponsor = address(0x6666666666666666666666666666666666666666);
        vm.etch(targetAddress, address(distributor).code);
        RoyaltyDistributor target = RoyaltyDistributor(payable(targetAddress));

        RoyaltyDistributor.FundingReservationRequest memory request;
        request.settlementId = _repeatByte(0x01);
        request.settlementNonce = 7;
        request.releasePolicyCommitment = _repeatByte(0x02);
        request.roomCommitment = _repeatByte(0x03);
        request.roomStateCommitment = _repeatByte(0x04);
        request.queryCommitment = _repeatByte(0x05);
        request.grantSetCommitment = _repeatByte(0x06);
        request.allocationCommitment = _repeatByte(0x07);
        request.ownersAmountsHash = _repeatByte(0x08);
        request.asset = address(0x7777777777777777777777777777777777777777);
        request.total = 123_456_789;
        request.executionCommitment = _repeatByte(0x09);
        request.refundAfter = 1_800_003_600;

        assertEq(
            target.fundingReservationId(sponsor, request),
            0xd0d62c115a12faf9651d4218dd1afb623b46248be0200645058fbd422d50f53f
        );
    }

    function test_RejectsValueMismatchWithoutConsumingReplay() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.6 ether, 0.4 ether, 13, keccak256("value-mismatch"));
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ValueMismatch.selector);
        distributor.distributeNative{value: 0.9 ether}(
            authorization, owners, amounts, settlementSignature, qvlSignature
        );
        assertFalse(distributor.processedSettlements(authorization.settlementId));
    }

    function test_RejectsTotalMismatchWithoutConsumingReplay() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.6 ether, 0.4 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 2 ether, 14, keccak256("total-mismatch"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.TotalMismatch.selector);
        distributor.distributeNative{value: 2 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
        assertFalse(distributor.processedSettlements(authorization.settlementId));
    }

    function test_PausedSettlementStillAllowsExistingWithdrawals() public {
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(0.7 ether, 0.3 ether, 15, keccak256("pause-withdraw"));
        vm.prank(payer);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);
        distributor.setPaused(true);

        vm.prank(ownerA);
        distributor.withdraw();
        assertEq(ownerA.balance, 0.7 ether);
        assertEq(distributor.pending(address(0), ownerA), 0);
    }

    // -- ERC20 exact-delta settlement --------------------------------

    function test_DistributeERC20CreditsAndPullsExactFunds() public {
        MockRoyaltyERC20 token = new MockRoyaltyERC20();
        token.mint(payer, 1_000_000);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 16, keccak256("erc20"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);

        vm.startPrank(payer);
        token.approve(address(distributor), 1_000_000);
        distributor.distributeERC20(authorization, owners, amounts, settlementSignature, qvlSignature);
        vm.stopPrank();

        assertEq(distributor.pending(address(token), ownerA), 700_000);
        assertEq(distributor.pending(address(token), ownerB), 300_000);
        vm.prank(ownerA);
        distributor.withdraw(address(token));
        vm.prank(ownerB);
        distributor.withdraw(address(token));
        assertEq(token.balanceOf(ownerA), 700_000);
        assertEq(token.balanceOf(ownerB), 300_000);
        assertEq(token.balanceOf(address(distributor)), 0);
    }

    function test_DistributeERC20RejectsPhantomFundingAndPreservesReplay() public {
        RoyaltyPhantomERC20 token = new RoyaltyPhantomERC20();
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 17, keccak256("phantom-in"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);

        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.TokenAmountMismatch.selector);
        distributor.distributeERC20(authorization, owners, amounts, settlementSignature, qvlSignature);
        assertFalse(distributor.processedSettlements(authorization.settlementId));
        assertEq(distributor.pending(address(token), ownerA), 0);
    }

    function test_WithdrawERC20RejectsPhantomPayoutAndPreservesClaim() public {
        RoyaltyOutboundPhantomERC20 token = new RoyaltyOutboundPhantomERC20();
        token.mint(payer, 1_000_000);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 18, keccak256("phantom-out"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);
        vm.startPrank(payer);
        token.approve(address(distributor), 1_000_000);
        distributor.distributeERC20(authorization, owners, amounts, settlementSignature, qvlSignature);
        vm.stopPrank();

        vm.prank(ownerA);
        vm.expectRevert(RoyaltyDistributor.TokenAmountMismatch.selector);
        distributor.withdraw(address(token));
        assertEq(distributor.pending(address(token), ownerA), 700_000);
        assertEq(token.balanceOf(ownerA), 0);
    }

    function test_ERC20CallbackCannotReenterSettlementAccounting() public {
        RoyaltyCallbackERC20 token = new RoyaltyCallbackERC20(distributor);
        token.mint(payer, 1_000_000);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 29, keccak256("token-callback"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);

        vm.startPrank(payer);
        token.approve(address(distributor), 1_000_000);
        distributor.distributeERC20(authorization, owners, amounts, settlementSignature, qvlSignature);
        vm.stopPrank();

        assertTrue(token.callbackBlocked());
        assertEq(distributor.pending(address(token), ownerA), 700_000);
        assertEq(distributor.pending(address(token), ownerB), 300_000);
        assertEq(token.balanceOf(address(distributor)), 1_000_000);
    }

    // -- Intent-keyed prefunding reservations ------------------------

    function test_NativeReservationFinalizedViewAndOneShotSettlement() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.7 ether, 0.3 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 31, keccak256("reserved-native"), owners, amounts);
        uint64 refundAfter = uint64(block.timestamp + 1 days);
        RoyaltyDistributor.FundingReservationRequest memory request = _reservationRequest(authorization, refundAfter);

        vm.prank(payer);
        bytes32 reservationId = distributor.reserveNative{value: 1 ether}(request);
        assertEq(reservationId, distributor.fundingReservationId(payer, request));

        RoyaltyDistributor.FundingReservationView memory viewState =
            distributor.collaborationFundingReservation(reservationId);
        assertTrue(viewState.active);
        assertFalse(viewState.consumed);
        assertEq(viewState.sponsor, payer);
        assertEq(viewState.asset, address(0));
        assertEq(viewState.total, 1 ether);
        assertEq(viewState.ownerAmountsHash, authorization.ownersAmountsHash);
        assertEq(viewState.releasePolicyCommitment, authorization.releasePolicyCommitment);
        assertEq(viewState.executionIntentCommitment, authorization.executionCommitment);
        assertEq(viewState.refundAfter, refundAfter);
        assertEq(viewState.depositedAmount, 1 ether);
        assertEq(distributor.totalReserved(address(0)), 1 ether);
        assertEq(distributor.totalPending(address(0)), 0);

        bytes memory settlementSignature;
        bytes memory qvlSignature;
        (authorization, settlementSignature, qvlSignature) = _bindReservationAndSign(authorization, reservationId);
        address relayer = makeAddr("reservation-relayer");
        vm.prank(relayer);
        distributor.settleReserved(reservationId, authorization, owners, amounts, settlementSignature, qvlSignature);

        viewState = distributor.collaborationFundingReservation(reservationId);
        assertFalse(viewState.active);
        assertTrue(viewState.consumed);
        assertEq(viewState.depositedAmount, 0);
        assertEq(distributor.totalReserved(address(0)), 0);
        assertEq(distributor.totalPending(address(0)), 1 ether);
        assertEq(distributor.pending(address(0), ownerA), 0.7 ether);
        assertEq(distributor.pending(address(0), ownerB), 0.3 ether);

        RoyaltyDistributor.FundingReservationSettlementView memory settlementState =
            distributor.fundingReservationSettlementState(reservationId);
        assertTrue(settlementState.consumed);
        assertTrue(settlementState.settlementProcessed);
        assertTrue(settlementState.nonceProcessed);
        assertEq(settlementState.settlementId, authorization.settlementId);
        assertEq(settlementState.settlementNonce, authorization.settlementNonce);
        assertEq(settlementState.asset, authorization.asset);
        assertEq(settlementState.total, authorization.total);
        assertEq(settlementState.ownerAmountsHash, authorization.ownersAmountsHash);

        vm.expectRevert(RoyaltyDistributor.ReservationNotActive.selector);
        distributor.settleReserved(reservationId, authorization, owners, amounts, settlementSignature, qvlSignature);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ReservationNotActive.selector);
        distributor.refundFundingReservation(reservationId);

        vm.prank(ownerA);
        distributor.withdraw();
        vm.prank(ownerB);
        distributor.withdraw();
        assertEq(distributor.totalPending(address(0)), 0);
        assertEq(address(distributor).balance, 0);
    }

    function test_BalanceAndAllowanceWithoutReservationCannotUnlockSettlement() public {
        MockRoyaltyERC20 token = new MockRoyaltyERC20();
        token.mint(payer, 1_000_000);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 32, keccak256("allowance-only"), owners, amounts);
        RoyaltyDistributor.FundingReservationRequest memory request =
            _reservationRequest(authorization, uint64(block.timestamp + 1 days));
        bytes32 reservationId = distributor.fundingReservationId(payer, request);
        bytes memory settlementSignature;
        bytes memory qvlSignature;
        (authorization, settlementSignature, qvlSignature) = _bindReservationAndSign(authorization, reservationId);

        vm.prank(payer);
        token.approve(address(distributor), type(uint256).max);
        vm.expectRevert(RoyaltyDistributor.ReservationMissing.selector);
        distributor.settleReserved(reservationId, authorization, owners, amounts, settlementSignature, qvlSignature);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.SettlementReservationMismatch.selector);
        distributor.distributeERC20(authorization, owners, amounts, settlementSignature, qvlSignature);
        assertEq(token.balanceOf(address(distributor)), 0);
        assertFalse(distributor.processedSettlements(authorization.settlementId));
    }

    function test_ERC20ReservationSurvivesSponsorDrainAndAllowanceRevocation() public {
        MockRoyaltyERC20 token = new MockRoyaltyERC20();
        token.mint(payer, 2_000_000);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 33, keccak256("escrow-survives"), owners, amounts);
        RoyaltyDistributor.FundingReservationRequest memory request =
            _reservationRequest(authorization, uint64(block.timestamp + 1 days));

        vm.startPrank(payer);
        token.approve(address(distributor), 1_000_000);
        bytes32 reservationId = distributor.reserveERC20(request);
        token.approve(address(distributor), 0);
        token.transfer(makeAddr("drained-to"), 1_000_000);
        vm.stopPrank();
        assertEq(token.balanceOf(payer), 0);
        assertEq(token.allowance(payer, address(distributor)), 0);

        bytes memory settlementSignature;
        bytes memory qvlSignature;
        (authorization, settlementSignature, qvlSignature) = _bindReservationAndSign(authorization, reservationId);
        distributor.settleReserved(reservationId, authorization, owners, amounts, settlementSignature, qvlSignature);
        assertEq(distributor.totalReserved(address(token)), 0);
        assertEq(distributor.totalPending(address(token)), 1_000_000);
        assertEq(token.balanceOf(address(distributor)), 1_000_000);
        assertEq(distributor.pending(address(token), ownerA), 700_000);
        assertEq(distributor.pending(address(token), ownerB), 300_000);
    }

    function test_ReservationRejectsFeeOnTransferIngressWithoutRecordingState() public {
        RoyaltyFeeOnTransferERC20 token = new RoyaltyFeeOnTransferERC20();
        token.mint(payer, 1_000_000);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 34, keccak256("fee-reserve"), owners, amounts);
        RoyaltyDistributor.FundingReservationRequest memory request =
            _reservationRequest(authorization, uint64(block.timestamp + 1 days));
        bytes32 reservationId = distributor.fundingReservationId(payer, request);

        vm.startPrank(payer);
        token.approve(address(distributor), 1_000_000);
        vm.expectRevert(RoyaltyDistributor.TokenAmountMismatch.selector);
        distributor.reserveERC20(request);
        vm.stopPrank();
        (RoyaltyDistributor.FundingReservation memory stored, bool active) =
            distributor.fundingReservationState(reservationId);
        assertEq(uint256(stored.status), uint256(RoyaltyDistributor.FundingReservationStatus.None));
        assertFalse(active);
        assertEq(distributor.totalReserved(address(token)), 0);
        assertEq(token.balanceOf(address(distributor)), 0);
    }

    function test_ReservationRequiresUnpausedStableRelease() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.7 ether, 0.3 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 35, keccak256("stable-release"), owners, amounts);
        RoyaltyDistributor.FundingReservationRequest memory request =
            _reservationRequest(authorization, uint64(block.timestamp + 1 days));

        distributor.proposeAuthorityBinding(
            makeAddr("pending-settlement"), makeAddr("pending-qvl"), address(anchor), ANCHOR_WRITER_RELEASE
        );
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ProposalExists.selector);
        distributor.reserveNative{value: 1 ether}(request);
        distributor.cancelAuthorityProposal();
        distributor.setPaused(true);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.Paused.selector);
        distributor.reserveNative{value: 1 ether}(request);
    }

    function test_ReservationSettlementAndRefundHaveDisjointDeadlineBoundary() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.7 ether, 0.3 ether);
        RoyaltyDistributor.SettlementAuthorization memory first =
            _authorization(address(0), 1 ether, 36, keccak256("deadline-settle"), owners, amounts);
        uint64 firstRefundAfter = uint64(block.timestamp + first.expiry - block.timestamp);
        RoyaltyDistributor.FundingReservationRequest memory firstRequest = _reservationRequest(first, firstRefundAfter);
        vm.prank(payer);
        bytes32 firstId = distributor.reserveNative{value: 1 ether}(firstRequest);
        bytes memory firstSettlementSignature;
        bytes memory firstQvlSignature;
        (first, firstSettlementSignature, firstQvlSignature) = _bindReservationAndSign(first, firstId);

        vm.warp(firstRefundAfter - 1);
        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(RoyaltyDistributor.ReservationNotExpired.selector, firstRefundAfter));
        distributor.refundFundingReservation(firstId);
        distributor.settleReserved(firstId, first, owners, amounts, firstSettlementSignature, firstQvlSignature);
        vm.warp(firstRefundAfter);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ReservationNotActive.selector);
        distributor.refundFundingReservation(firstId);

        RoyaltyDistributor.SettlementAuthorization memory second =
            _authorization(address(0), 1 ether, 37, keccak256("deadline-refund"), owners, amounts);
        uint64 secondRefundAfter = uint64(second.expiry);
        RoyaltyDistributor.FundingReservationRequest memory secondRequest =
            _reservationRequest(second, secondRefundAfter);
        vm.prank(payer);
        bytes32 secondId = distributor.reserveNative{value: 1 ether}(secondRequest);
        bytes memory secondSettlementSignature;
        bytes memory secondQvlSignature;
        (second, secondSettlementSignature, secondQvlSignature) = _bindReservationAndSign(second, secondId);
        vm.warp(secondRefundAfter);
        vm.expectRevert(RoyaltyDistributor.ReservationExpired.selector);
        distributor.settleReserved(secondId, second, owners, amounts, secondSettlementSignature, secondQvlSignature);
        uint256 payerBefore = payer.balance;
        vm.prank(payer);
        distributor.refundFundingReservation(secondId);
        assertEq(payer.balance, payerBefore + 1 ether);
        vm.prank(payer);
        vm.expectRevert(RoyaltyDistributor.ReservationNotActive.selector);
        distributor.refundFundingReservation(secondId);
    }

    function test_RotationInvalidatesOldPolicyReservationButCannotBlockRefund() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.7 ether, 0.3 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 38, keccak256("rotation-refund"), owners, amounts);
        uint64 refundAfter = uint64(block.timestamp + 3 days);
        RoyaltyDistributor.FundingReservationRequest memory request = _reservationRequest(authorization, refundAfter);
        vm.prank(payer);
        bytes32 reservationId = distributor.reserveNative{value: 1 ether}(request);
        bytes memory settlementSignature;
        bytes memory qvlSignature;
        (authorization, settlementSignature, qvlSignature) = _bindReservationAndSign(authorization, reservationId);

        distributor.proposeAuthorityBinding(
            makeAddr("rotated-settlement"), makeAddr("rotated-qvl"), address(anchor), ANCHOR_WRITER_RELEASE
        );
        vm.warp(distributor.pendingAuthorityActivatesAt());
        distributor.activateAuthorityProposal();
        authorization.expiry = block.timestamp + distributor.MAX_AUTHORIZATION_LIFETIME();
        (authorization, settlementSignature, qvlSignature) = _bindReservationAndSign(authorization, reservationId);
        vm.expectRevert(RoyaltyDistributor.ReleasePolicyMismatch.selector);
        distributor.settleReserved(reservationId, authorization, owners, amounts, settlementSignature, qvlSignature);
        distributor.setPaused(true);
        vm.warp(refundAfter);
        vm.prank(payer);
        distributor.refundFundingReservation(reservationId);
        assertEq(distributor.totalReserved(address(0)), 0);
    }

    function test_ReservationIntentMutationFailsClosed() public {
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.7 ether, 0.3 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 39, keccak256("intent-mutation"), owners, amounts);
        RoyaltyDistributor.FundingReservationRequest memory request =
            _reservationRequest(authorization, uint64(block.timestamp + 1 days));
        vm.prank(payer);
        bytes32 reservationId = distributor.reserveNative{value: 1 ether}(request);
        authorization.executionCommitment = keccak256("mutated-execution-intent");
        bytes memory settlementSignature;
        bytes memory qvlSignature;
        (authorization, settlementSignature, qvlSignature) = _bindReservationAndSign(authorization, reservationId);
        vm.expectRevert(RoyaltyDistributor.SettlementReservationMismatch.selector);
        distributor.settleReserved(reservationId, authorization, owners, amounts, settlementSignature, qvlSignature);
        assertEq(distributor.totalReserved(address(0)), 1 ether);
        assertFalse(distributor.processedSettlements(authorization.settlementId));
    }

    function test_ERC20ReservationIngressCallbackCannotReenter() public {
        RoyaltyCallbackERC20 token = new RoyaltyCallbackERC20(distributor);
        token.mint(payer, 1_000_000);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(700_000, 300_000);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(token), 1_000_000, 40, keccak256("reserve-callback"), owners, amounts);
        RoyaltyDistributor.FundingReservationRequest memory request =
            _reservationRequest(authorization, uint64(block.timestamp + 1 days));
        vm.startPrank(payer);
        token.approve(address(distributor), 1_000_000);
        bytes32 reservationId = distributor.reserveERC20(request);
        vm.stopPrank();
        assertTrue(token.callbackBlocked());
        assertTrue(distributor.collaborationFundingReservation(reservationId).active);
        assertEq(distributor.totalReserved(address(token)), 1_000_000);
    }

    function test_NativeRefundReentrancyCannotDoubleRefund() public {
        ReentrantReservationSponsor sponsor = new ReentrantReservationSponsor(distributor);
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.7 ether, 0.3 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 41, keccak256("refund-reentry"), owners, amounts);
        uint64 refundAfter = uint64(block.timestamp + 1 hours);
        RoyaltyDistributor.FundingReservationRequest memory request = _reservationRequest(authorization, refundAfter);
        vm.deal(address(this), 1 ether);
        sponsor.reserve{value: 1 ether}(request);
        vm.warp(refundAfter);
        sponsor.refund();
        assertTrue(sponsor.callbackBlocked());
        assertEq(sponsor.received(), 1 ether);
        assertEq(distributor.totalReserved(address(0)), 0);
        (RoyaltyDistributor.FundingReservation memory stored,) =
            distributor.fundingReservationState(sponsor.reservationId());
        assertEq(uint256(stored.status), uint256(RoyaltyDistributor.FundingReservationStatus.Refunded));
    }

    function testFuzz_ReservedNativeConservation(uint96 rawA, uint96 rawB) public {
        uint256 a = bound(uint256(rawA), 1, 10 ether);
        uint256 b = bound(uint256(rawB), 1, 10 ether);
        uint256 total = a + b;
        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(a, b);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), total, 42, keccak256(abi.encode("reserved-fuzz", a, b)), owners, amounts);
        RoyaltyDistributor.FundingReservationRequest memory request =
            _reservationRequest(authorization, uint64(block.timestamp + 1 days));
        vm.deal(payer, total);
        vm.prank(payer);
        bytes32 reservationId = distributor.reserveNative{value: total}(request);
        bytes memory settlementSignature;
        bytes memory qvlSignature;
        (authorization, settlementSignature, qvlSignature) = _bindReservationAndSign(authorization, reservationId);
        distributor.settleReserved(reservationId, authorization, owners, amounts, settlementSignature, qvlSignature);
        assertEq(distributor.totalReserved(address(0)) + distributor.totalPending(address(0)), total);
        assertEq(address(distributor).balance, total);
        vm.prank(ownerA);
        distributor.withdraw();
        vm.prank(ownerB);
        distributor.withdraw();
        assertEq(distributor.totalReserved(address(0)) + distributor.totalPending(address(0)), 0);
        assertEq(address(distributor).balance, 0);
    }

    // -- Contract signatures, fuzzing, and reentrancy ----------------

    function test_SupportsDistinctERC1271ReleaseSigners() public {
        MockRoyalty1271Signer settlement1271 = new MockRoyalty1271Signer();
        MockRoyalty1271Signer qvl1271 = new MockRoyalty1271Signer();
        distributor.proposeAuthorityBinding(
            address(settlement1271), address(qvl1271), address(anchor), ANCHOR_WRITER_RELEASE
        );
        vm.warp(distributor.pendingAuthorityActivatesAt());
        distributor.activateAuthorityProposal();

        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.6 ether, 0.4 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 19, keccak256("1271"), owners, amounts);
        settlement1271.approve(distributor.settlementAuthorizationDigest(authorization));
        qvl1271.approve(distributor.settlementQvlAuthorizationDigest(authorization));

        vm.prank(payer);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, hex"01", hex"02");
        assertEq(distributor.pending(address(0), ownerA), 0.6 ether);
    }

    function test_ERC1271StaticCallbackCannotMutateDistributor() public {
        RoyaltyCallback1271Signer settlement1271 = new RoyaltyCallback1271Signer(distributor);
        MockRoyalty1271Signer qvl1271 = new MockRoyalty1271Signer();
        distributor.proposeAuthorityBinding(
            address(settlement1271), address(qvl1271), address(anchor), ANCHOR_WRITER_RELEASE
        );
        vm.warp(distributor.pendingAuthorityActivatesAt());
        distributor.activateAuthorityProposal();

        address[] memory owners = _owners();
        uint256[] memory amounts = _amounts(0.6 ether, 0.4 ether);
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 1 ether, 30, keccak256("1271-static-callback"), owners, amounts);
        settlement1271.approve(distributor.settlementAuthorizationDigest(authorization));
        qvl1271.approve(distributor.settlementQvlAuthorizationDigest(authorization));

        vm.prank(payer);
        distributor.distributeNative{value: 1 ether}(authorization, owners, amounts, hex"01", hex"02");
        assertFalse(distributor.paused());
        assertEq(distributor.pending(address(0), ownerA), 0.6 ether);
    }

    function testFuzz_NativeConservation(uint96 rawA, uint96 rawB) public {
        uint256 a = bound(uint256(rawA), 1, 10 ether);
        uint256 b = bound(uint256(rawB), 1, 10 ether);
        uint256 total = a + b;
        (
            RoyaltyDistributor.SettlementAuthorization memory authorization,
            address[] memory owners,
            uint256[] memory amounts,
            bytes memory settlementSignature,
            bytes memory qvlSignature
        ) = _prepareNative(a, b, 20, keccak256(abi.encode(a, b)));
        vm.deal(payer, total);
        vm.prank(payer);
        distributor.distributeNative{value: total}(authorization, owners, amounts, settlementSignature, qvlSignature);

        vm.prank(ownerA);
        distributor.withdraw();
        vm.prank(ownerB);
        distributor.withdraw();
        assertEq(ownerA.balance + ownerB.balance, total);
        assertEq(address(distributor).balance, 0);
    }

    function test_WithdrawReentrancyCannotDoublePay() public {
        ReentrantRoyaltyClaimer attacker = new ReentrantRoyaltyClaimer(distributor);
        address[] memory owners = _sortedOwners(address(attacker), ownerB);
        uint256[] memory amounts = new uint256[](2);
        uint256 attackerIndex = owners[0] == address(attacker) ? 0 : 1;
        amounts[attackerIndex] = 3 ether;
        amounts[1 - attackerIndex] = 1 ether;
        RoyaltyDistributor.SettlementAuthorization memory authorization =
            _authorization(address(0), 4 ether, 21, keccak256("reentrant"), owners, amounts);
        (bytes memory settlementSignature, bytes memory qvlSignature) = _sign(authorization);
        vm.prank(payer);
        distributor.distributeNative{value: 4 ether}(authorization, owners, amounts, settlementSignature, qvlSignature);

        attacker.claim();
        assertEq(attacker.received(), 3 ether);
        assertEq(distributor.pending(address(0), address(attacker)), 0);
        assertEq(address(distributor).balance, 1 ether);
    }

    function test_DirectNativeCustodyIsDisabled() public {
        vm.prank(payer);
        (bool ok, bytes memory data) = address(distributor).call{value: 1 ether}("");
        assertFalse(ok);
        assertEq(bytes4(data), RoyaltyDistributor.DirectCustodyDisabled.selector);
    }
}
