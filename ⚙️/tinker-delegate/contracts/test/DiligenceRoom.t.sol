// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DiligenceRoom} from "../src/DiligenceRoom.sol";

contract RevertingReceiver {
    DiligenceRoom internal immutable room;

    constructor(DiligenceRoom _room) {
        room = _room;
    }

    function createDeal(uint256 reservePrice, uint256 expiry, bytes32 artifactHash, address teeIdentity)
        external
        returns (uint256)
    {
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

    function fund(uint256 dealId, uint256 amount, bytes32 evaluatorPolicyCommitment) external {
        room.fundDeal{value: amount}(dealId, evaluatorPolicyCommitment);
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
            // Re-entrant withdraw must revert; swallow it so we can assert the
            // single legitimate payout landed.
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

    function transfer(address to, uint256 amount) external virtual returns (bool) {
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

/// @dev Accepts collateral normally but returns success without paying an
///      outbound claim. Exact recipient/sender deltas must reject the payout.
contract OutboundPhantomERC20 is MockERC20 {
    function transfer(address, uint256) external pure override returns (bool) {
        return true;
    }
}

/// @dev Returns success from transferFrom without transferring any collateral.
contract PhantomFundingERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return true;
    }
}

/// @dev Burns one percent during transferFrom, modeling a fee-on-transfer token.
contract FeeOnTransferERC20 {
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
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - (amount / 100);
        return true;
    }
}

contract DiligenceRoomTest is Test {
    uint256 internal constant SECP256K1_FULL_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    DiligenceRoom public room;
    bytes32 internal constant RESULT_AUTHORIZATION_TYPEHASH = keccak256(
        "DiligenceRoomResultAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,bytes32 resultHash,bytes32 attestationReleasePolicyHash,uint256 authorizationExpiry)"
    );
    bytes32 internal constant ATTESTATION_AUTHORIZATION_TYPEHASH = keccak256(
        "DiligenceRoomQVLAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,bytes32 resultHash,bytes32 attestationReleasePolicyHash,bytes32 attestationEvidenceHash,uint256 authorizationExpiry)"
    );
    bytes32 internal constant PUBLIC_RESULT_TYPEHASH = keccak256(
        "DiligenceRoomPublicResult(uint256 chainId,address contractAddress,uint256 dealId,address seller,address buyer,uint256 reservePrice,uint256 budgetCap,uint256 expiry,bytes32 artifactHash,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,uint8 scoreBand,uint256 computeCost)"
    );

    address dev = address(this);
    address seller = makeAddr("seller");
    address buyer = makeAddr("buyer");
    address tee = makeAddr("tee");
    uint256 verifierPk = 0xA11CE;
    address verifier;
    uint256 attestationVerifierPk = 0xDCA9;
    address attestationVerifier;
    bytes32 attestationReleasePolicyHash = keccak256("diligence-qvl-release-policy");
    bytes32 evaluatorPolicyCommitment = keccak256("deterministic-bounded-no-network-recipe-v1");
    bytes32 evaluatorPolicyCommitmentTwo = keccak256("deterministic-bounded-no-network-recipe-v2");
    bytes32 evaluatorPolicyCommitmentThree = keccak256("deterministic-bounded-no-network-recipe-v3");
    bytes32 attestationEvidenceHash = keccak256("bounded-qvl-evidence-v1");

    uint256 reservePrice = 0.5 ether;
    uint256 budgetCap = 2 ether;
    uint256 expiry;
    bytes32 artifactCommitmentSecret = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    bytes32 artifactCommitmentFixture = 0x0f5dd8f2c3fba9bcd4d19565c66257757094f11017d8f3fdd264c7b0b5156d80;
    bytes32 artifactHash = keccak256(
        abi.encodePacked(
            "dnai-wikigen/artifact-commitment/v2", bytes1(0), artifactCommitmentSecret, bytes("test-artifact")
        )
    );
    bytes32 composeHash = keccak256("delegate-compose-v1");

    function setUp() public {
        verifier = vm.addr(verifierPk);
        attestationVerifier = vm.addr(attestationVerifierPk);
        room = new DiligenceRoom(false);
        room.proposeResultVerifier(verifier);
        vm.warp(room.pendingResultVerifierActivatesAt());
        room.activateResultVerifier();
        room.freezeResultVerifier();
        room.proposeAttestationBinding(attestationVerifier, attestationReleasePolicyHash);
        vm.warp(room.pendingAttestationBindingActivatesAt());
        room.activateAttestationBinding();
        room.freezeAttestationBinding();
        expiry = block.timestamp + 1 days;
        vm.deal(buyer, 10 ether);
    }

    function test_FreshRoomLeavesResultVerifierUnsetAndCannotFreezeIt() public {
        DiligenceRoom fresh = new DiligenceRoom(false);
        assertEq(fresh.developer(), address(this));
        assertEq(fresh.resultVerifier(), address(0));
        assertEq(fresh.pendingResultVerifier(), address(0));
        assertEq(fresh.pendingResultVerifierActivatesAt(), 0);
        assertFalse(fresh.resultVerifierFrozen());
        vm.expectRevert(DiligenceRoom.ResultVerifierNotReady.selector);
        fresh.freezeResultVerifier();
    }

    function test_ProductionConstructorIsFailClosedBeforeAnyConfigurationTransaction() public {
        DiligenceRoom production = new DiligenceRoom(true);
        assertTrue(production.productionRelease());
        assertFalse(production.approvalRequirementsFrozen());

        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        production.createDeal(1 ether, block.timestamp + 1 days, keccak256("artifact"), tee);

        assertEq(production.dealCount(), 0);
    }

    function test_ResultVerifierRequiresDeveloperTimelockActivationAndFreeze() public {
        DiligenceRoom fresh = new DiligenceRoom(false);
        address proposedVerifier = makeAddr("post-deploy-result-verifier");
        address unauthorized = makeAddr("unauthorized-result-verifier-governor");

        vm.prank(unauthorized);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        fresh.proposeResultVerifier(proposedVerifier);

        vm.expectRevert(DiligenceRoom.ZeroResultVerifier.selector);
        fresh.proposeResultVerifier(address(0));
        vm.expectRevert(DiligenceRoom.RoleConflict.selector);
        fresh.proposeResultVerifier(address(this));

        fresh.proposeResultVerifier(proposedVerifier);
        uint256 activatesAt = fresh.pendingResultVerifierActivatesAt();
        assertEq(fresh.pendingResultVerifier(), proposedVerifier);
        assertEq(activatesAt, block.timestamp + fresh.ATTESTATION_BINDING_TIMELOCK_DELAY());

        vm.expectRevert(abi.encodeWithSelector(DiligenceRoom.ResultVerifierActivationTooEarly.selector, activatesAt));
        fresh.activateResultVerifier();
        vm.expectRevert(DiligenceRoom.ResultVerifierProposalExists.selector);
        fresh.proposeResultVerifier(makeAddr("second-pending-result-verifier"));

        fresh.cancelResultVerifierProposal();
        assertEq(fresh.pendingResultVerifier(), address(0));
        assertEq(fresh.pendingResultVerifierActivatesAt(), 0);

        fresh.proposeResultVerifier(proposedVerifier);
        vm.warp(fresh.pendingResultVerifierActivatesAt());
        fresh.activateResultVerifier();
        assertEq(fresh.resultVerifier(), proposedVerifier);
        assertEq(fresh.pendingResultVerifier(), address(0));
        assertEq(fresh.pendingResultVerifierActivatesAt(), 0);

        fresh.freezeResultVerifier();
        assertTrue(fresh.resultVerifierFrozen());
        vm.expectRevert(DiligenceRoom.ResultVerifierBindingFrozenError.selector);
        fresh.proposeResultVerifier(makeAddr("post-freeze-result-verifier"));
    }

    // ── Helpers ────────────────────────────────────────────────────────

    function _createDeal() internal returns (uint256) {
        expiry = block.timestamp + 1 days;
        vm.prank(seller);
        return room.createDeal(reservePrice, expiry, artifactHash, tee);
    }

    function _fundDeal(uint256 dealId) internal {
        vm.prank(buyer);
        room.fundDeal{value: budgetCap}(dealId, evaluatorPolicyCommitment);
    }

    function _admitCompose(bytes32 admittedComposeHash) internal {
        room.proposeComposeHash(admittedComposeHash);
        vm.warp(room.pendingComposeActivations(admittedComposeHash));
        room.activateComposeHash(admittedComposeHash);
        expiry = block.timestamp + 1 days;
    }

    function _admitTee(address admittedTee, bytes32 admittedComposeHash) internal {
        room.proposeTeeIdentity(admittedTee, admittedComposeHash);
        vm.warp(room.pendingTeeIdentityActivations(admittedTee));
        room.activateTeeIdentity(admittedTee);
        expiry = block.timestamp + 1 days;
    }

    function _submitResult(uint256 dealId, DiligenceRoom.ScoreBand band, uint256 computeCost) internal {
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory signature = _authorizationSignature(dealId, band, computeCost, authorizationExpiry);
        bytes memory qvlSignature = _attestationSignature(dealId, band, computeCost, attestationEvidenceHash, qvlExpiry);
        vm.prank(tee);
        room.submitResult(
            dealId,
            band,
            computeCost,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function _freezeAttestationBinding() internal {
        if (!room.attestationBindingFrozen()) {
            room.proposeAttestationBinding(attestationVerifier, attestationReleasePolicyHash);
            vm.warp(room.pendingAttestationBindingActivatesAt());
            room.activateAttestationBinding();
            room.freezeAttestationBinding();
        }
        room.freezeFeeBps();
        room.enableComputeSettlementPolicy();
        if (!room.evaluatorPolicySetFrozen()) _admitEvaluatorPolicySet();
        room.freezeComposeAdditions();
        room.freezeTeeIdentityAdditions();
        expiry = block.timestamp + 1 days;
    }

    function _releaseEvaluatorPolicies() internal view returns (bytes32[3] memory policies) {
        policies = [evaluatorPolicyCommitment, evaluatorPolicyCommitmentTwo, evaluatorPolicyCommitmentThree];
    }

    function _admitEvaluatorPolicySet() internal {
        bytes32[3] memory policies = _releaseEvaluatorPolicies();
        room.proposeEvaluatorPolicySet(policies);
        vm.warp(room.pendingEvaluatorPolicyActivations(policies[0]));
        room.activateEvaluatorPolicySet(policies);
        room.freezeEvaluatorPolicySet();
        expiry = block.timestamp + 1 days;
    }

    function _resetRoomWithoutAttestationBinding() internal {
        room = new DiligenceRoom(false);
        room.proposeResultVerifier(verifier);
        vm.warp(room.pendingResultVerifierActivatesAt());
        room.activateResultVerifier();
        room.freezeResultVerifier();
        expiry = block.timestamp + 1 days;
    }

    function _configureFullyFrozenAuthorizationBindings(DiligenceRoom target, bytes32 releasePolicyHash) internal {
        target.proposeResultVerifier(verifier);
        vm.warp(target.pendingResultVerifierActivatesAt());
        target.activateResultVerifier();
        target.freezeResultVerifier();
        target.proposeAttestationBinding(attestationVerifier, releasePolicyHash);
        vm.warp(target.pendingAttestationBindingActivatesAt());
        target.activateAttestationBinding();
        target.freezeAttestationBinding();
    }

    function _authorizationSignature(
        uint256 dealId,
        DiligenceRoom.ScoreBand band,
        uint256 computeCost,
        uint256 authorizationExpiry
    ) internal view returns (bytes memory) {
        bytes32 resultHash = _canonicalResultHash(dealId, composeHash, band, computeCost);
        bytes32 digest = _authorizationDigest(dealId, tee, composeHash, resultHash, authorizationExpiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierPk, _ethSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _attestationSignature(
        uint256 dealId,
        DiligenceRoom.ScoreBand band,
        uint256 computeCost,
        bytes32 evidenceHash,
        uint256 authorizationExpiry
    ) internal view returns (bytes memory) {
        bytes32 resultHash = _canonicalResultHash(dealId, composeHash, band, computeCost);
        bytes32 digest =
            _attestationAuthorizationDigest(dealId, tee, composeHash, resultHash, evidenceHash, authorizationExpiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attestationVerifierPk, _ethSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _canonicalResultHash(
        uint256 dealId,
        bytes32 resultComposeHash,
        DiligenceRoom.ScoreBand band,
        uint256 computeCost
    ) internal view returns (bytes32) {
        DiligenceRoom.Deal memory d = room.getDeal(dealId);
        return keccak256(
            abi.encode(
                PUBLIC_RESULT_TYPEHASH,
                block.chainid,
                address(room),
                dealId,
                d.seller,
                d.buyer,
                d.reservePrice,
                d.budgetCap,
                d.expiry,
                d.artifactHash,
                d.teeIdentity,
                resultComposeHash,
                d.evaluatorPolicyCommitment,
                uint8(band),
                computeCost
            )
        );
    }

    function _authorizationDigest(
        uint256 dealId,
        address teeIdentity,
        bytes32 resultComposeHash,
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
                room.getDeal(dealId).evaluatorPolicyCommitment,
                resultHash,
                room.attestationReleasePolicyHash(),
                authorizationExpiry
            )
        );
    }

    function _attestationAuthorizationDigest(
        uint256 dealId,
        address teeIdentity,
        bytes32 resultComposeHash,
        bytes32 resultHash,
        bytes32 evidenceHash,
        uint256 authorizationExpiry
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                ATTESTATION_AUTHORIZATION_TYPEHASH,
                block.chainid,
                address(room),
                dealId,
                teeIdentity,
                resultComposeHash,
                room.getDeal(dealId).evaluatorPolicyCommitment,
                resultHash,
                room.attestationReleasePolicyHash(),
                evidenceHash,
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

    function test_ArtifactCommitmentFixtureIsDomainSeparatedAndSalted() public view {
        assertEq(artifactHash, artifactCommitmentFixture);
        assertEq(
            artifactHash,
            keccak256(
                abi.encodePacked(
                    "dnai-wikigen/artifact-commitment/v2", bytes1(0), artifactCommitmentSecret, bytes("test-artifact")
                )
            )
        );
        assertNotEq(artifactHash, keccak256("test-artifact"));
        assertNotEq(
            artifactHash,
            keccak256(
                abi.encodePacked(
                    "dnai-wikigen/artifact-commitment/v2", bytes1(0), bytes32(uint256(1)), bytes("test-artifact")
                )
            )
        );
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
        assertEq(d.evaluatorPolicyCommitment, evaluatorPolicyCommitment);
        assertEq(uint8(d.state), uint8(DiligenceRoom.State.Funded));
    }

    function test_FundDealAtomicallyBindsNonzeroPolicyAndCannotRebind() public {
        uint256 id = _createDeal();

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.ZeroEvaluatorPolicyCommitment.selector);
        room.fundDeal{value: budgetCap}(id, bytes32(0));

        DiligenceRoom.Deal memory beforeFunding = room.getDeal(id);
        assertEq(beforeFunding.buyer, address(0));
        assertEq(beforeFunding.evaluatorPolicyCommitment, bytes32(0));
        assertEq(uint8(beforeFunding.state), uint8(DiligenceRoom.State.Created));

        _fundDeal(id);
        bytes32 competingRecipe = keccak256("competing-recipe");
        address competingBuyer = makeAddr("competing-buyer");
        vm.deal(competingBuyer, budgetCap);
        vm.prank(competingBuyer);
        vm.expectRevert(
            abi.encodeWithSelector(
                DiligenceRoom.InvalidState.selector, DiligenceRoom.State.Created, DiligenceRoom.State.Funded
            )
        );
        room.fundDeal{value: budgetCap}(id, competingRecipe);

        DiligenceRoom.Deal memory funded = room.getDeal(id);
        assertEq(funded.buyer, buyer);
        assertEq(funded.evaluatorPolicyCommitment, evaluatorPolicyCommitment);
    }

    function test_ProductionLegacyFundingOverloadsAreUnavailable() public {
        DiligenceRoom production = new DiligenceRoom(true);

        vm.expectRevert(DiligenceRoom.LegacyFundingUnavailable.selector);
        production.fundDeal(0);
        vm.expectRevert(DiligenceRoom.LegacyFundingUnavailable.selector);
        production.fundDealERC20(0, 1);
    }

    function test_EvaluatorPolicySetRejectsDuplicatesAndFreezesOnlyExactThree() public {
        bytes32[3] memory duplicatePolicies =
            [evaluatorPolicyCommitment, evaluatorPolicyCommitment, evaluatorPolicyCommitmentThree];
        vm.expectRevert(DiligenceRoom.AdmissionProposalExists.selector);
        room.proposeEvaluatorPolicySet(duplicatePolicies);
        assertEq(room.pendingEvaluatorPolicyCount(), 0);

        bytes32[3] memory policies = _releaseEvaluatorPolicies();
        room.proposeEvaluatorPolicy(policies[0]);
        vm.expectRevert(DiligenceRoom.EvaluatorPolicySetNotExact.selector);
        room.freezeEvaluatorPolicySet();
        vm.expectRevert(
            abi.encodeWithSelector(
                DiligenceRoom.AdmissionActivationTooEarly.selector, room.pendingEvaluatorPolicyActivations(policies[0])
            )
        );
        room.activateEvaluatorPolicy(policies[0]);
        room.cancelEvaluatorPolicyProposal(policies[0]);
        assertEq(room.pendingEvaluatorPolicyCount(), 0);
    }

    function test_EvaluatorPolicyCanBeRemovedBeforeFreezeAndSetRootIsOrderIndependent() public {
        bytes32[3] memory policies = _releaseEvaluatorPolicies();
        room.proposeEvaluatorPolicySet(policies);
        vm.warp(room.pendingEvaluatorPolicyActivations(policies[0]));
        room.activateEvaluatorPolicySet(policies);
        room.removeEvaluatorPolicy(policies[1]);
        assertFalse(room.approvedEvaluatorPolicies(policies[1]));
        assertEq(room.approvedEvaluatorPolicyCount(), 2);

        room.proposeEvaluatorPolicy(policies[1]);
        vm.warp(room.pendingEvaluatorPolicyActivations(policies[1]));
        room.activateEvaluatorPolicy(policies[1]);
        room.freezeEvaluatorPolicySet();

        bytes32[3] memory reversed = [policies[2], policies[1], policies[0]];
        assertEq(room.evaluatorPolicySetRoot(), room.computeEvaluatorPolicySetRoot(reversed));
        assertEq(room.approvedEvaluatorPolicyCount(), 3);
        assertEq(room.pendingEvaluatorPolicyCount(), 0);
        vm.expectRevert(DiligenceRoom.EvaluatorPolicySetFrozenError.selector);
        room.removeEvaluatorPolicy(policies[0]);
        vm.expectRevert(DiligenceRoom.EvaluatorPolicySetFrozenError.selector);
        room.proposeEvaluatorPolicy(keccak256("fourth-policy"));
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

    function testFuzz_FundDeal_RevertBelowReserve(uint256 amount) public {
        amount = bound(amount, 1, reservePrice - 1);
        uint256 id = _createDeal();

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.InsufficientFunding.selector);
        room.fundDeal{value: amount}(id);

        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Created));
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
        assertEq(d.evaluatorPolicyCommitment, evaluatorPolicyCommitment);
        assertEq(d.attestationEvidenceHash, attestationEvidenceHash);
        assertGt(d.resultAuthorizationExpiry, block.timestamp);
        assertGt(d.attestationAuthorizationExpiry, block.timestamp);
    }

    function test_ComputeSettlementPolicy_IsOneWayAndDeveloperOnly() public {
        assertFalse(room.computeSettlementPolicyEnabled());

        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.enableComputeSettlementPolicy();

        room.enableComputeSettlementPolicy();
        assertTrue(room.computeSettlementPolicyEnabled());
        vm.expectRevert(DiligenceRoom.ComputeSettlementPolicyAlreadyEnabled.selector);
        room.enableComputeSettlementPolicy();
    }

    function test_ComputeSettlementPolicy_RejectsMeterModulationAndAcceptsTariff() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        room.freezeFeeBps();
        room.enableComputeSettlementPolicy();

        uint256 expected = room.policyComputeCost(id);
        assertEq(expected, budgetCap / 100);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 evaluatorModulatedCost = expected + 123_456_789;
        bytes memory modulatedSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, evaluatorModulatedCost, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature = _attestationSignature(
            id, DiligenceRoom.ScoreBand.High, evaluatorModulatedCost, attestationEvidenceHash, qvlExpiry
        );

        vm.prank(tee);
        vm.expectRevert(
            abi.encodeWithSelector(
                DiligenceRoom.ComputeSettlementPolicyMismatch.selector, expected, evaluatorModulatedCost
            )
        );
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            evaluatorModulatedCost,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            modulatedSignature,
            qvlSignature
        );

        _submitResult(id, DiligenceRoom.ScoreBand.High, expected);
        DiligenceRoom.Deal memory d = room.getDeal(id);
        assertEq(d.computeCost, expected);
        assertEq(d.fee, expected / 100);
    }

    function test_ComputeSettlementPolicy_CapsTariffToPreserveReserve() public {
        uint256 tightReserve = budgetCap - 1_000;
        vm.prank(seller);
        uint256 id = room.createDeal(tightReserve, expiry, artifactHash, tee);
        _fundDeal(id);
        room.freezeFeeBps();
        room.enableComputeSettlementPolicy();

        uint256 compute = room.policyComputeCost(id);
        uint256 fee = (compute * room.feeBps()) / 10000;
        assertLe(compute, budgetCap / 100);
        assertLe(tightReserve + compute + fee, budgetCap);
    }

    function test_SubmitResult_RevertNotTEE() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotTEE.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertWrongState() public {
        uint256 id = _createDeal();
        // Not funded yet
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);
        vm.prank(tee);
        vm.expectRevert();
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertComputeCostOverBudget() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 1.99 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 1.99 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComputeCostOverBudget.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            1.99 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertZeroComposeHash() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ZeroComposeHash.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            bytes32(0),
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_CanonicalResultHashIsContractDerivedAndStored() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 computeCost = 0.1 ether;
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes32 expected = _canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.High, computeCost);
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, computeCost, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, computeCost, attestationEvidenceHash, qvlExpiry);

        assertEq(room.PUBLIC_RESULT_TYPEHASH(), PUBLIC_RESULT_TYPEHASH);
        assertEq(room.canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.High, computeCost), expected);
        assertNotEq(room.canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.Medium, computeCost), expected);

        vm.prank(tee);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            computeCost,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );

        assertEq(room.getDeal(id).resultHash, expected);
    }

    function test_CanonicalPublicResultHardcodedParityVector() public pure {
        assertEq(PUBLIC_RESULT_TYPEHASH, 0xcc7808e2d534524498257da49708e62cc622bfddd641a5e5f3560882b0ce4c46);

        bytes32 actual = keccak256(
            abi.encode(
                PUBLIC_RESULT_TYPEHASH,
                uint256(84532),
                address(0x1111111111111111111111111111111111111111),
                uint256(7),
                address(0x2222222222222222222222222222222222222222),
                address(0x3333333333333333333333333333333333333333),
                uint256(500000000000000000),
                uint256(2000000000000000000),
                uint256(1800000000),
                bytes32(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa),
                address(0x4444444444444444444444444444444444444444),
                bytes32(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb),
                bytes32(0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc),
                uint8(2),
                uint256(20000000000000000)
            )
        );

        assertEq(actual, 0x76d9e72181f1906242b7e0a1484b8aef5c1057a6b93734d3f37d5b6c09b0195a);
    }

    function test_ResultAuthorizationDigestBindsCanonicalPublicResult() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        DiligenceRoom.ScoreBand band = DiligenceRoom.ScoreBand.Medium;
        uint256 computeCost = 0.1 ether;
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes32 resultHash = _canonicalResultHash(id, composeHash, band, computeCost);
        bytes32 expected = _authorizationDigest(id, tee, composeHash, resultHash, authorizationExpiry);

        assertEq(room.resultAuthorizationDigest(id, composeHash, band, computeCost, authorizationExpiry), expected);
    }

    function test_SubmitResult_RevertExpiredAuthorization() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp - 1;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.AuthorizationExpired.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertInvalidAuthorizationSigner() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes32 resultHash = _canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.High, 0.1 ether);
        bytes32 digest = _authorizationDigest(id, tee, composeHash, resultHash, authorizationExpiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, _ethSignedMessageHash(digest));
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            abi.encodePacked(r, s, v),
            qvlSignature
        );
    }

    function test_SubmitResult_RevertMalleatedHighSSignature() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes32 resultHash = _canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.High, 0.1 ether);
        bytes32 digest = _authorizationDigest(id, tee, composeHash, resultHash, authorizationExpiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierPk, _ethSignedMessageHash(digest));
        bytes32 highS = bytes32(SECP256K1_FULL_ORDER - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            abi.encodePacked(r, highS, flippedV),
            qvlSignature
        );
    }

    function test_SubmitResult_RevertWrongIndependentQVLSigner() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes32 resultHash = _canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.High, 0.1 ether);
        bytes32 qvlDigest =
            _attestationAuthorizationDigest(id, tee, composeHash, resultHash, attestationEvidenceHash, qvlExpiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierPk, _ethSignedMessageHash(qvlDigest));

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidAttestationAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            resultSignature,
            abi.encodePacked(r, s, v)
        );
    }

    function test_SubmitResult_RevertAttestationEvidenceDrift() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);
        bytes32 driftedEvidenceHash = keccak256("different-bounded-qvl-evidence");

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidAttestationAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            driftedEvidenceHash,
            qvlExpiry,
            resultSignature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertMalleatedHighSQVLSignature() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes32 resultHash = _canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.High, 0.1 ether);
        bytes32 qvlDigest =
            _attestationAuthorizationDigest(id, tee, composeHash, resultHash, attestationEvidenceHash, qvlExpiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attestationVerifierPk, _ethSignedMessageHash(qvlDigest));
        bytes32 highS = bytes32(SECP256K1_FULL_ORDER - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidAttestationAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            resultSignature,
            abi.encodePacked(r, highS, flippedV)
        );
    }

    function test_SubmitResult_RevertZeroAttestationEvidenceHash() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ZeroAttestationEvidenceHash.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            bytes32(0),
            qvlExpiry,
            resultSignature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertExpiredQVLAuthorization() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.AttestationAuthorizationExpired.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            resultSignature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertAuthorizationLifetimeOverTenMinutes() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 10 minutes + 1;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.AuthorizationLifetimeTooLong.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            resultSignature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertQVLLifetimeOverTenMinutes() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp + 10 minutes + 1;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.AuthorizationLifetimeTooLong.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            resultSignature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertWhenIndependentQVLBindingIsNotFrozen() public {
        _resetRoomWithoutAttestationBinding();
        room.proposeAttestationBinding(attestationVerifier, attestationReleasePolicyHash);
        vm.warp(room.pendingAttestationBindingActivatesAt());
        room.activateAttestationBinding();
        expiry = block.timestamp + 1 days;
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory resultSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            resultSignature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertResultSignatureFromAnotherRoom() public {
        DiligenceRoom firstRoom = room;
        DiligenceRoom secondRoom = new DiligenceRoom(false);
        _configureFullyFrozenAuthorizationBindings(secondRoom, attestationReleasePolicyHash);
        expiry = block.timestamp + 1 days;

        room = firstRoom;
        uint256 firstDealId = _createDeal();
        _fundDeal(firstDealId);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory firstRoomResultSignature =
            _authorizationSignature(firstDealId, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);

        room = secondRoom;
        uint256 secondDealId = _createDeal();
        _fundDeal(secondDealId);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory secondRoomQvlSignature = _attestationSignature(
            secondDealId, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry
        );

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            secondDealId,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            firstRoomResultSignature,
            secondRoomQvlSignature
        );
    }

    function test_SubmitResult_RevertSignatureForAnotherChain() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory oldChainSignature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);

        vm.chainId(block.chainid + 1);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory newChainQvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            oldChainSignature,
            newChainQvlSignature
        );
    }

    function test_SubmitResult_RevertSignatureForAnotherAttestationPolicy() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes32 resultHash = _canonicalResultHash(id, composeHash, DiligenceRoom.ScoreBand.High, 0.1 ether);
        bytes32 forgedDigest = keccak256(
            abi.encode(
                RESULT_AUTHORIZATION_TYPEHASH,
                block.chainid,
                address(room),
                id,
                tee,
                composeHash,
                evaluatorPolicyCommitment,
                resultHash,
                keccak256("different-frozen-attestation-policy"),
                authorizationExpiry
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierPk, _ethSignedMessageHash(forgedDigest));
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);

        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            abi.encodePacked(r, s, v),
            qvlSignature
        );
    }

    // ── On-chain compose-approval gate ─────────────────────────────────

    function test_ComposeApprovalDefaultsOff() public {
        assertEq(room.composeApprovalRequired(), false);
        assertEq(room.approvedComposeHashes(composeHash), false);
        // With the gate off, submission works even for an unapproved compose.
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.02 ether);
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Evaluated));
    }

    function test_ProposeComposeHash_OnlyDeveloper() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.proposeComposeHash(composeHash);
    }

    function test_SetComposeApprovalRequired_OnlyDeveloper() public {
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.setComposeApprovalRequired(true);
    }

    function test_ProposeComposeHash_RevertZero() public {
        vm.expectRevert(DiligenceRoom.ZeroComposeHash.selector);
        room.proposeComposeHash(bytes32(0));
    }

    function test_SubmitResult_RevertComposeNotApprovedWhenRequired() public {
        room.setComposeApprovalRequired(true);
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_SubmitResult_SucceedsWhenComposeApproved() public {
        room.setComposeApprovalRequired(true);
        _admitCompose(composeHash);
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Evaluated));
        assertEq(room.getDeal(id).resultComposeHash, composeHash);
    }

    function test_RevokeComposeHash_BlocksSubmit() public {
        room.setComposeApprovalRequired(true);
        _admitCompose(composeHash);
        room.revokeComposeHash(composeHash);
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
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

    function test_ProposeTeeIdentity_OnlyDeveloper() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.proposeTeeIdentity(tee, composeHash);
    }

    function test_ProposeTeeIdentity_RevertZeroAddressOrHash() public {
        vm.expectRevert(DiligenceRoom.ZeroTEEIdentity.selector);
        room.proposeTeeIdentity(address(0), composeHash);
        vm.expectRevert(DiligenceRoom.ZeroComposeHash.selector);
        room.proposeTeeIdentity(tee, bytes32(0));
    }

    function test_CreateDeal_RevertTeeIdentityNotApprovedWhenRequired() public {
        room.setTeeIdentityApprovalRequired(true);
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.TeeIdentityNotApproved.selector);
        room.createDeal(reservePrice, expiry, artifactHash, tee);
    }

    function test_CreateDeal_SucceedsWhenTeeIdentityApproved() public {
        room.setTeeIdentityApprovalRequired(true);
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        uint256 id = _createDeal();
        assertEq(room.getDeal(id).teeIdentity, tee);
    }

    function test_SubmitResult_SucceedsWhenIdentityComposeMatches() public {
        room.setTeeIdentityApprovalRequired(true);
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Evaluated));
    }

    function test_SubmitResult_RevertWhenIdentityComposeMismatch() public {
        // Identity bound to a DIFFERENT measurement than the one submitted.
        bytes32 otherCompose = keccak256("delegate-compose-v2");
        _admitCompose(otherCompose);
        _admitTee(tee, otherCompose);
        room.setTeeIdentityApprovalRequired(true);
        uint256 id = _createDeal();
        _fundDeal(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.ComposeHashIdentityMismatch.selector);
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_RevokeTeeIdentity_BlocksCreate() public {
        room.setTeeIdentityApprovalRequired(true);
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
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

    function test_FreezeApprovalRequirements_RequiresDeveloperAndBothGates() public {
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.NotDeveloper.selector);
        room.freezeApprovalRequirements();

        vm.expectRevert(DiligenceRoom.ApprovalRequirementsNotEnabled.selector);
        room.freezeApprovalRequirements();

        room.setComposeApprovalRequired(true);
        vm.expectRevert(DiligenceRoom.ApprovalRequirementsNotEnabled.selector);
        room.freezeApprovalRequirements();

        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();
        assertTrue(room.approvalRequirementsFrozen());

        vm.expectRevert(DiligenceRoom.ApprovalRequirementsFrozenError.selector);
        room.freezeApprovalRequirements();
    }

    function test_FrozenApprovalRequirementsAreFailClosedAndAdmissionsRemainStagedBeforeClosure() public {
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();

        vm.expectRevert(DiligenceRoom.ApprovalRequirementsFrozenError.selector);
        room.setComposeApprovalRequired(false);
        vm.expectRevert(DiligenceRoom.ApprovalRequirementsFrozenError.selector);
        room.setTeeIdentityApprovalRequired(false);

        // Empty identity/compose mappings make the frozen release fail-closed.
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        room.createDeal(reservePrice, expiry, artifactHash, tee);

        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        _freezeAttestationBinding();
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.02 ether);

        room.revokeComposeHash(composeHash);
        room.revokeTeeIdentity(tee);
        assertFalse(room.approvedComposeHashes(composeHash));
        assertEq(room.teeIdentityComposeHash(tee), bytes32(0));
    }

    function test_FrozenReleaseRejectsUnsupportedEvaluatorPolicyWithoutGriefingDeal() public {
        _admitEvaluatorPolicySet();
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();
        _freezeAttestationBinding();

        uint256 id = _createDeal();
        bytes32 unsupportedPolicy = keccak256("unsupported-arbitrary-python-policy");
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.EvaluatorPolicyNotApproved.selector);
        room.fundDeal{value: budgetCap}(id, unsupportedPolicy);

        DiligenceRoom.Deal memory stillOpen = room.getDeal(id);
        assertEq(stillOpen.buyer, address(0));
        assertEq(stillOpen.evaluatorPolicyCommitment, bytes32(0));
        assertEq(uint8(stillOpen.state), uint8(DiligenceRoom.State.Created));
        _fundDeal(id);
    }

    function test_AttestationBindingIsTimelockedExactAndPermanentlyFreezable() public {
        _resetRoomWithoutAttestationBinding();
        assertEq(room.attestationVerifier(), address(0));
        assertEq(room.attestationReleasePolicyHash(), bytes32(0));
        assertFalse(room.attestationBindingFrozen());

        room.proposeAttestationBinding(attestationVerifier, attestationReleasePolicyHash);
        uint256 activatesAt = block.timestamp + room.ATTESTATION_BINDING_TIMELOCK_DELAY();
        assertEq(room.pendingAttestationVerifier(), attestationVerifier);
        assertEq(room.pendingAttestationReleasePolicyHash(), attestationReleasePolicyHash);
        assertEq(room.pendingAttestationBindingActivatesAt(), activatesAt);

        vm.expectRevert(
            abi.encodeWithSelector(DiligenceRoom.AttestationBindingActivationTooEarly.selector, activatesAt)
        );
        room.activateAttestationBinding();

        vm.warp(activatesAt);
        room.activateAttestationBinding();
        assertEq(room.attestationVerifier(), attestationVerifier);
        assertEq(room.attestationReleasePolicyHash(), attestationReleasePolicyHash);
        assertEq(room.pendingAttestationBindingActivatesAt(), 0);

        room.freezeAttestationBinding();
        assertTrue(room.attestationBindingFrozen());
        vm.expectRevert(DiligenceRoom.AttestationBindingFrozenError.selector);
        room.proposeAttestationBinding(makeAddr("replacement-qvl"), keccak256("replacement-policy"));
        vm.expectRevert(DiligenceRoom.AttestationBindingFrozenError.selector);
        room.freezeAttestationBinding();
    }

    function test_AttestationBindingProposalCanBeCancelledAndRejectsControlRoles() public {
        _resetRoomWithoutAttestationBinding();
        vm.expectRevert(DiligenceRoom.ZeroAttestationVerifier.selector);
        room.proposeAttestationBinding(address(0), attestationReleasePolicyHash);
        vm.expectRevert(DiligenceRoom.ZeroAttestationReleasePolicyHash.selector);
        room.proposeAttestationBinding(attestationVerifier, bytes32(0));
        vm.expectRevert(DiligenceRoom.RoleConflict.selector);
        room.proposeAttestationBinding(dev, attestationReleasePolicyHash);
        vm.expectRevert(DiligenceRoom.RoleConflict.selector);
        room.proposeAttestationBinding(verifier, attestationReleasePolicyHash);
        vm.expectRevert(DiligenceRoom.RoleConflict.selector);
        room.proposeAttestationBinding(address(room), attestationReleasePolicyHash);

        room.proposeAttestationBinding(attestationVerifier, attestationReleasePolicyHash);
        vm.expectRevert(DiligenceRoom.AttestationBindingProposalExists.selector);
        room.proposeAttestationBinding(makeAddr("other-qvl"), keccak256("other-policy"));
        room.cancelAttestationBindingProposal();
        assertEq(room.pendingAttestationVerifier(), address(0));
        assertEq(room.pendingAttestationReleasePolicyHash(), bytes32(0));
        assertEq(room.pendingAttestationBindingActivatesAt(), 0);
        vm.expectRevert(DiligenceRoom.AttestationBindingProposalMissing.selector);
        room.cancelAttestationBindingProposal();
    }

    function test_ProductionLifecycleCannotCreateFundOrSubmitUntilBindingIsFrozen() public {
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);

        expiry = block.timestamp + 7 days;
        vm.startPrank(seller);
        uint256 id = room.createDeal(reservePrice, expiry, artifactHash, tee);
        uint256 fundedBeforeFreeze = room.createDeal(reservePrice, expiry, artifactHash, tee);
        vm.stopPrank();
        _fundDeal(fundedBeforeFreeze);
        room.freezeApprovalRequirements();
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        room.createDeal(reservePrice, expiry, artifactHash, tee);
        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        room.fundDeal{value: budgetCap}(id);
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(fundedBeforeFreeze, DiligenceRoom.ScoreBand.High, 0.02 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature = _attestationSignature(
            fundedBeforeFreeze, DiligenceRoom.ScoreBand.High, 0.02 ether, attestationEvidenceHash, qvlExpiry
        );
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        room.submitResult(
            fundedBeforeFreeze,
            DiligenceRoom.ScoreBand.High,
            0.02 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );

        _freezeAttestationBinding();
        _fundDeal(id);
        _submitResult(fundedBeforeFreeze, DiligenceRoom.ScoreBand.High, 0.02 ether);
        assertEq(uint8(room.getDeal(fundedBeforeFreeze).state), uint8(DiligenceRoom.State.Evaluated));
    }

    function test_ProductionMarkerRequiresEveryFrozenReleaseControl() public {
        _resetRoomWithoutAttestationBinding();
        _admitEvaluatorPolicySet();
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();

        room.proposeAttestationBinding(attestationVerifier, attestationReleasePolicyHash);
        vm.warp(room.pendingAttestationBindingActivatesAt());
        room.activateAttestationBinding();
        room.freezeAttestationBinding();

        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        _createDeal();

        room.freezeFeeBps();
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        _createDeal();

        room.enableComputeSettlementPolicy();
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        _createDeal();

        room.freezeComposeAdditions();
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        _createDeal();

        room.freezeTeeIdentityAdditions();
        uint256 id = _createDeal();
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Created));
    }

    function test_ProductionMarkerRejectsExtraAdmissionEvenWhenFrozen() public {
        _resetRoomWithoutAttestationBinding();
        _admitEvaluatorPolicySet();
        _admitCompose(composeHash);
        _admitCompose(keccak256("unexpected-second-compose"));
        _admitTee(tee, composeHash);
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();
        room.proposeAttestationBinding(attestationVerifier, attestationReleasePolicyHash);
        vm.warp(room.pendingAttestationBindingActivatesAt());
        room.activateAttestationBinding();
        room.freezeAttestationBinding();
        room.freezeFeeBps();
        room.enableComputeSettlementPolicy();
        room.freezeComposeAdditions();
        room.freezeTeeIdentityAdditions();

        assertEq(room.approvedComposeCount(), 2);
        vm.expectRevert(DiligenceRoom.AttestationBindingNotReady.selector);
        _createDeal();
    }

    function test_AdmissionDefaultsAreEmptyAndOpenForStaging() public view {
        assertFalse(room.composeAdditionsFrozen());
        assertFalse(room.teeIdentityAdditionsFrozen());
        assertEq(room.approvedComposeCount(), 0);
        assertEq(room.pendingComposeCount(), 0);
        assertEq(room.approvedTeeIdentityCount(), 0);
        assertEq(room.pendingTeeIdentityCount(), 0);
    }

    function test_ComposeAdmissionIsTimelockedAndExactlyCounted() public {
        room.proposeComposeHash(composeHash);
        uint256 activatesAt = block.timestamp + room.ADMISSION_TIMELOCK_DELAY();
        assertEq(room.pendingComposeActivations(composeHash), activatesAt);
        assertEq(room.pendingComposeCount(), 1);
        assertEq(room.approvedComposeCount(), 0);
        vm.expectRevert(DiligenceRoom.AdmissionProposalExists.selector);
        room.proposeComposeHash(composeHash);
        vm.expectRevert(abi.encodeWithSelector(DiligenceRoom.AdmissionActivationTooEarly.selector, activatesAt));
        room.activateComposeHash(composeHash);

        vm.warp(activatesAt);
        room.activateComposeHash(composeHash);
        assertEq(room.pendingComposeActivations(composeHash), 0);
        assertEq(room.pendingComposeCount(), 0);
        assertEq(room.approvedComposeCount(), 1);
        assertTrue(room.approvedComposeHashes(composeHash));
    }

    function test_ComposeProposalCancellationMaintainsExactPendingCount() public {
        room.proposeComposeHash(composeHash);
        room.cancelComposeHashProposal(composeHash);
        assertEq(room.pendingComposeActivations(composeHash), 0);
        assertEq(room.pendingComposeCount(), 0);
        vm.expectRevert(DiligenceRoom.AdmissionProposalMissing.selector);
        room.cancelComposeHashProposal(composeHash);
    }

    function testFuzz_ComposeAdmissionDelayCannotBeShortened(uint64 elapsed) public {
        elapsed = uint64(bound(elapsed, 0, room.ADMISSION_TIMELOCK_DELAY() - 1));
        room.proposeComposeHash(composeHash);
        uint256 activatesAt = room.pendingComposeActivations(composeHash);
        vm.warp(block.timestamp + elapsed);
        vm.expectRevert(abi.encodeWithSelector(DiligenceRoom.AdmissionActivationTooEarly.selector, activatesAt));
        room.activateComposeHash(composeHash);
    }

    function test_TeeAdmissionRequiresActiveComposeAndIsExactlyCounted() public {
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.proposeTeeIdentity(tee, composeHash);
        _admitCompose(composeHash);

        vm.expectRevert(DiligenceRoom.RoleConflict.selector);
        room.proposeTeeIdentity(dev, composeHash);
        vm.expectRevert(DiligenceRoom.RoleConflict.selector);
        room.proposeTeeIdentity(verifier, composeHash);
        room.proposeTeeIdentity(tee, composeHash);
        uint256 activatesAt = block.timestamp + room.ADMISSION_TIMELOCK_DELAY();
        assertEq(room.pendingTeeIdentityComposeHash(tee), composeHash);
        assertEq(room.pendingTeeIdentityActivations(tee), activatesAt);
        assertEq(room.pendingTeeIdentityCount(), 1);
        assertEq(room.approvedTeeIdentityCount(), 0);
        vm.expectRevert(abi.encodeWithSelector(DiligenceRoom.AdmissionActivationTooEarly.selector, activatesAt));
        room.activateTeeIdentity(tee);

        vm.warp(activatesAt);
        room.activateTeeIdentity(tee);
        assertEq(room.pendingTeeIdentityCount(), 0);
        assertEq(room.approvedTeeIdentityCount(), 1);
        assertEq(room.teeIdentityComposeHash(tee), composeHash);
    }

    function test_TeeProposalCancellationMaintainsExactPendingCount() public {
        _admitCompose(composeHash);
        room.proposeTeeIdentity(tee, composeHash);
        room.cancelTeeIdentityProposal(tee);
        assertEq(room.pendingTeeIdentityActivations(tee), 0);
        assertEq(room.pendingTeeIdentityComposeHash(tee), bytes32(0));
        assertEq(room.pendingTeeIdentityCount(), 0);
        vm.expectRevert(DiligenceRoom.AdmissionProposalMissing.selector);
        room.cancelTeeIdentityProposal(tee);
    }

    function test_ComposeEmergencyRevocationBlocksPendingTeeActivation() public {
        _admitCompose(composeHash);
        room.proposeTeeIdentity(tee, composeHash);
        vm.warp(room.pendingTeeIdentityActivations(tee));
        room.revokeComposeHash(composeHash);
        assertEq(room.approvedComposeCount(), 0);
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.activateTeeIdentity(tee);
        assertEq(room.pendingTeeIdentityCount(), 1);
    }

    function test_AdmissionFreezesRequireNonemptySetsAndNoPendingProposals() public {
        vm.expectRevert(DiligenceRoom.EmptyAdmissionSet.selector);
        room.freezeComposeAdditions();
        room.proposeComposeHash(composeHash);
        vm.expectRevert(DiligenceRoom.PendingAdmissions.selector);
        room.freezeComposeAdditions();
        vm.warp(room.pendingComposeActivations(composeHash));
        room.activateComposeHash(composeHash);
        room.freezeComposeAdditions();

        vm.expectRevert(DiligenceRoom.EmptyAdmissionSet.selector);
        room.freezeTeeIdentityAdditions();
        room.proposeTeeIdentity(tee, composeHash);
        vm.expectRevert(DiligenceRoom.PendingAdmissions.selector);
        room.freezeTeeIdentityAdditions();
        vm.warp(room.pendingTeeIdentityActivations(tee));
        room.activateTeeIdentity(tee);
        room.freezeTeeIdentityAdditions();
    }

    function test_ClosedAdmissionSetBlocksAdditionsButAllowsEmergencyRevocation() public {
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        room.freezeComposeAdditions();
        room.freezeTeeIdentityAdditions();
        assertTrue(room.composeAdditionsFrozen());
        assertTrue(room.teeIdentityAdditionsFrozen());
        vm.expectRevert(DiligenceRoom.AdmissionAdditionsFrozen.selector);
        room.proposeComposeHash(keccak256("replacement-compose"));
        vm.expectRevert(DiligenceRoom.AdmissionAdditionsFrozen.selector);
        room.proposeTeeIdentity(makeAddr("replacement-tee"), composeHash);

        room.revokeTeeIdentity(tee);
        room.revokeComposeHash(composeHash);
        assertEq(room.approvedTeeIdentityCount(), 0);
        assertEq(room.approvedComposeCount(), 0);
        vm.expectRevert(DiligenceRoom.TeeIdentityNotApproved.selector);
        room.revokeTeeIdentity(tee);
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.revokeComposeHash(composeHash);
    }

    function test_RevokedComposeImmediatelyBlocksNewDealsForStillBoundIdentity() public {
        room.setTeeIdentityApprovalRequired(true);
        _admitCompose(composeHash);
        _admitTee(tee, composeHash);
        room.revokeComposeHash(composeHash);
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.ComposeHashNotApproved.selector);
        room.createDeal(reservePrice, block.timestamp + 1 days, artifactHash, tee);
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

    function test_NonexistentDealCannotBeReadOrExpired() public {
        uint256 nonexistentId = room.dealCount();

        vm.expectRevert(DiligenceRoom.DealNotFound.selector);
        room.getDeal(nonexistentId);

        vm.expectRevert(DiligenceRoom.DealNotFound.selector);
        room.expireDeal(nonexistentId);

        assertEq(room.dealCount(), 0);
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

        uint256 totalPending = room.pendingWithdrawals(address(0), seller) + room.pendingWithdrawals(address(0), dev)
            + room.pendingWithdrawals(address(0), buyer);

        assertEq(totalPending, budgetCap);
        assertEq(seller.balance + dev.balance + buyer.balance - totalBefore, 0);
    }

    // ── Settlement-path edge cases ─────────────────────────────────────

    function test_SubmitResult_RevertDoubleSubmit() public {
        uint256 id = _createDeal();
        _fundDeal(id);
        _submitResult(id, DiligenceRoom.ScoreBand.High, 0.1 ether);

        // Deal is now Evaluated; a second submit must revert on the state guard.
        uint256 authorizationExpiry = block.timestamp + 5 minutes;
        bytes memory signature =
            _authorizationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature =
            _attestationSignature(id, DiligenceRoom.ScoreBand.High, 0.1 ether, attestationEvidenceHash, qvlExpiry);
        vm.prank(tee);
        vm.expectRevert(
            abi.encodeWithSelector(
                DiligenceRoom.InvalidState.selector, DiligenceRoom.State.Funded, DiligenceRoom.State.Evaluated
            )
        );
        room.submitResult(
            id,
            DiligenceRoom.ScoreBand.High,
            0.1 ether,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            signature,
            qvlSignature
        );
    }

    function test_SubmitResult_RevertCrossDealAuthorizationReplay() public {
        uint256 dealA = _createDeal();
        _fundDeal(dealA);
        uint256 dealB = _createDeal();
        _fundDeal(dealB);

        DiligenceRoom.ScoreBand band = DiligenceRoom.ScoreBand.High;
        uint256 computeCost = 0.1 ether;
        uint256 authorizationExpiry = block.timestamp + 5 minutes;

        // An authorization signed for dealA binds dealId in its digest, so
        // replaying it on dealB recovers a non-verifier signer and is rejected.
        bytes memory sigForDealA = _authorizationSignature(dealA, band, computeCost, authorizationExpiry);
        uint256 qvlExpiry = block.timestamp + 4 minutes;
        bytes memory qvlSignature = _attestationSignature(dealB, band, computeCost, attestationEvidenceHash, qvlExpiry);
        vm.prank(tee);
        vm.expectRevert(DiligenceRoom.InvalidResultAuthorization.selector);
        room.submitResult(
            dealB,
            band,
            computeCost,
            composeHash,
            authorizationExpiry,
            attestationEvidenceHash,
            qvlExpiry,
            sigForDealA,
            qvlSignature
        );
    }

    function test_Withdraw_ReentrancyCannotDoublePay() public {
        ReentrantWithdrawer attacker = new ReentrantWithdrawer(room);
        vm.deal(address(attacker), budgetCap);

        uint256 id = _createDeal();
        attacker.fund(id, budgetCap, evaluatorPolicyCommitment); // attacker is the buyer
        _submitResult(id, DiligenceRoom.ScoreBand.Medium, 0.1 ether);
        attacker.reject(id); // accrues a refund to the attacker

        uint256 refund = room.pendingWithdrawals(address(0), address(attacker));
        assertGt(refund, 0);
        uint256 devPending = room.pendingWithdrawals(address(0), dev);

        attacker.attackWithdraw();

        // The attacker receives exactly its refund once; the re-entrant call was
        // blocked and could not double-withdraw.
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
        room.fundDealERC20(id, cap, evaluatorPolicyCommitment);
        vm.stopPrank();
    }

    function test_FundDealERC20AtomicallyBindsNonzeroPolicy() public {
        MockERC20 usdc = new MockERC20();
        uint256 cap = 2_000_000;
        uint256 id = _createTokenDeal(address(usdc));
        usdc.mint(buyer, cap);
        vm.startPrank(buyer);
        usdc.approve(address(room), cap);
        vm.expectRevert(DiligenceRoom.ZeroEvaluatorPolicyCommitment.selector);
        room.fundDealERC20(id, cap, bytes32(0));
        room.fundDealERC20(id, cap, evaluatorPolicyCommitment);
        vm.stopPrank();

        DiligenceRoom.Deal memory funded = room.getDeal(id);
        assertEq(funded.buyer, buyer);
        assertEq(funded.budgetCap, cap);
        assertEq(funded.evaluatorPolicyCommitment, evaluatorPolicyCommitment);
        assertEq(uint8(funded.state), uint8(DiligenceRoom.State.Funded));
    }

    function test_CreateDealERC20_RevertZeroToken() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.InvalidPaymentToken.selector);
        room.createDeal(TOKEN_RESERVE, expiry, artifactHash, tee, address(0));
    }

    function test_CreateDealERC20_RevertNonContractToken() public {
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.InvalidPaymentToken.selector);
        room.createDeal(TOKEN_RESERVE, expiry, artifactHash, tee, makeAddr("not-a-token"));
    }

    function test_ERC20_FullLifecycle_Accept() public {
        MockERC20 usdc = new MockERC20();
        uint256 cap = 2_000_000; // 2 USDC (6 decimals)
        uint256 compute = 100_000; // 0.1 USDC
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

        uint256 total = room.pendingWithdrawals(address(usdc), seller) + room.pendingWithdrawals(address(usdc), dev)
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

    function testFuzz_FundDealERC20_RevertBelowReserve(uint256 amount) public {
        MockERC20 usdc = new MockERC20();
        amount = bound(amount, 1, TOKEN_RESERVE - 1);
        uint256 id = _createTokenDeal(address(usdc));
        usdc.mint(buyer, amount);
        vm.startPrank(buyer);
        usdc.approve(address(room), amount);
        vm.expectRevert(DiligenceRoom.InsufficientFunding.selector);
        room.fundDealERC20(id, amount);
        vm.stopPrank();

        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Created));
        assertEq(usdc.balanceOf(address(room)), 0);
    }

    function test_FundDealERC20_RevertTokenLostCodeAfterCreation() public {
        MockERC20 usdc = new MockERC20();
        uint256 cap = 2_000_000;
        uint256 id = _createTokenDeal(address(usdc));
        usdc.mint(buyer, cap);
        vm.prank(buyer);
        usdc.approve(address(room), cap);
        vm.etch(address(usdc), hex"");

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.InvalidPaymentToken.selector);
        room.fundDealERC20(id, cap);
        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Created));
    }

    function test_FundDealERC20_RevertPhantomFunding() public {
        PhantomFundingERC20 phantom = new PhantomFundingERC20();
        uint256 cap = 2_000_000;
        uint256 id = _createTokenDeal(address(phantom));
        phantom.mint(buyer, cap);
        vm.startPrank(buyer);
        phantom.approve(address(room), cap);
        vm.expectRevert(DiligenceRoom.TokenAmountMismatch.selector);
        room.fundDealERC20(id, cap);
        vm.stopPrank();

        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Created));
        assertEq(phantom.balanceOf(address(room)), 0);
        assertEq(phantom.balanceOf(buyer), cap);
    }

    function test_FundDealERC20_RevertFeeOnTransferCollateral() public {
        FeeOnTransferERC20 taxed = new FeeOnTransferERC20();
        uint256 cap = 2_000_000;
        uint256 id = _createTokenDeal(address(taxed));
        taxed.mint(buyer, cap);
        vm.startPrank(buyer);
        taxed.approve(address(room), cap);
        vm.expectRevert(DiligenceRoom.TokenAmountMismatch.selector);
        room.fundDealERC20(id, cap);
        vm.stopPrank();

        assertEq(uint8(room.getDeal(id).state), uint8(DiligenceRoom.State.Created));
        assertEq(taxed.balanceOf(address(room)), 0);
        assertEq(taxed.balanceOf(buyer), cap);
    }

    function test_Withdraw_Token_RevertNothingToWithdraw() public {
        MockERC20 usdc = new MockERC20();
        vm.prank(seller);
        vm.expectRevert(DiligenceRoom.NothingToWithdraw.selector);
        room.withdraw(address(usdc));
    }

    function test_Withdraw_TokenRejectsPhantomPayoutAndPreservesClaim() public {
        OutboundPhantomERC20 phantom = new OutboundPhantomERC20();
        uint256 cap = 2_000_000;
        uint256 id = _createTokenDeal(address(phantom));
        _fundTokenDeal(phantom, id, cap);
        vm.warp(expiry + 1);
        room.expireDeal(id);

        vm.prank(buyer);
        vm.expectRevert(DiligenceRoom.TokenAmountMismatch.selector);
        room.withdraw(address(phantom));

        assertEq(room.pendingWithdrawals(address(phantom), buyer), cap);
        assertEq(phantom.balanceOf(buyer), 0);
        assertEq(phantom.balanceOf(address(room)), cap);
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
        vm.expectRevert(abi.encodeWithSelector(DiligenceRoom.FeeActivationTooEarly.selector, block.timestamp + 2 days));
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

        uint256 total = room.pendingWithdrawals(address(usdc), seller) + room.pendingWithdrawals(address(usdc), dev)
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

        uint256 total = room.pendingWithdrawals(address(usdc), dev) + room.pendingWithdrawals(address(usdc), buyer);
        assertEq(room.pendingWithdrawals(address(usdc), seller), 0);
        assertEq(room.pendingWithdrawals(address(usdc), dev), compute + fee);
        assertEq(total, cap);
    }

    function testFuzz_ERC20EndToEndWithdrawalConservation(uint256 cap, uint256 compute, uint256 payment) public {
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
        uint256 withdrawn = usdc.balanceOf(seller) + usdc.balanceOf(dev) + usdc.balanceOf(buyer);
        assertEq(withdrawn, cap);
    }

    // Allow receiving ETH (developer is this contract in tests)
    receive() external payable {}
}
