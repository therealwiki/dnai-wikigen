// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ComputeCreditVault} from "../src/ComputeCreditVault.sol";

contract ConfigurableCreditERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint16 public feeBps;
    bool public phantom;
    bool public returnFalse;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setBehavior(uint16 newFeeBps, bool newPhantom, bool newReturnFalse) external {
        feeBps = newFeeBps;
        phantom = newPhantom;
        returnFalse = newReturnFalse;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (returnFalse) return false;
        if (phantom) return true;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - ((amount * feeBps) / 10_000);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (returnFalse) return false;
        if (phantom) return true;
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - ((amount * feeBps) / 10_000);
        return true;
    }
}

contract MalformedBalanceToken {
    fallback() external payable {
        assembly {
            mstore(0, 1)
            return(31, 1)
        }
    }
}

contract Mock1271Signer {
    bytes32 public approvedDigest;
    bytes32 public approvedSignatureHash;
    bool public shouldRevert;

    function approve(bytes32 digest, bytes calldata signature) external {
        approvedDigest = digest;
        approvedSignatureHash = keccak256(signature);
    }

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        if (shouldRevert) revert("validator failure");
        if (digest == approvedDigest && keccak256(signature) == approvedSignatureHash) return 0x1626ba7e;
        return 0xffffffff;
    }
}

/// @dev Test-only state hook proving acceptOwnership independently validates
///      role state, even if it changes through a future governance extension.
contract ComputeCreditVaultRoleHarness is ComputeCreditVault {
    constructor(address initialOwner, address developerRecipient, uint16 feeBps)
        ComputeCreditVault(initialOwner, developerRecipient, feeBps)
    {}

    function forceProviderRole(address account) external {
        providerEverApproved[account] = true;
    }
}

contract RevertingCreditReceiver {
    ComputeCreditVault internal immutable vault;

    constructor(ComputeCreditVault target) {
        vault = target;
    }

    function withdraw(bytes32 projectId, uint256 amount) external {
        vault.withdrawUnused(projectId, address(0), amount);
    }

    receive() external payable {
        revert("refuse native payout");
    }
}

contract ReentrantCreditReceiver {
    ComputeCreditVault internal immutable vault;
    bytes32 internal projectId;
    uint256 internal attackAmount;
    bool internal entered;

    bool public reentrySucceeded;
    uint256 public received;

    constructor(ComputeCreditVault target) {
        vault = target;
    }

    function withdraw(bytes32 project, uint256 amount) external {
        projectId = project;
        attackAmount = amount;
        vault.withdrawUnused(project, address(0), amount);
    }

    receive() external payable {
        received += msg.value;
        if (!entered) {
            entered = true;
            (reentrySucceeded,) = address(vault)
                .call(abi.encodeCall(ComputeCreditVault.withdrawUnused, (projectId, address(0), attackAmount)));
        }
    }
}

abstract contract ComputeCreditVaultFixture is Test {
    struct MeteredTerms {
        bytes32 jobId;
        uint256 actualAssetDebit;
        uint256 billableComputeUnits;
        uint256 usageStartedAt;
        uint256 usageEndedAt;
        bytes32 attestationEvidenceHash;
        uint256 receiptExpiry;
    }

    struct ExactExecutionCommitments {
        bytes32 workload;
        bytes32 manifest;
        bytes32 dispatchIntent;
    }

    uint256 internal constant USER_KEY = 0xA11CE;
    uint256 internal constant VERIFIER_KEY = 0xB0B;
    uint256 internal constant QVL_KEY = 0xC0DE;
    uint256 internal constant SECP256K1_FULL_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    bytes32 internal constant PROJECT = keccak256("project-alpha");
    bytes32 internal constant NATIVE_POLICY = keccak256("native-rate-v1");
    bytes32 internal constant TOKEN_POLICY = keccak256("token-rate-v1");
    bytes32 internal constant COMPOSE_HASH = keccak256("reproducible-compose-digest");
    bytes32 internal constant METERING_POLICY_SET_HASH = keccak256("reviewed-metering-policy-set");
    bytes32 internal constant WORKLOAD = keccak256("reviewed-workload");
    bytes32 internal constant MANIFEST = keccak256("immutable-workload-manifest");
    bytes32 internal constant DISPATCH_INTENT = keccak256("signed-dispatch-intent");
    bytes32 internal constant ATTESTATION_EVIDENCE = keccak256("metering-tdx-evidence");
    uint256 internal constant BILLABLE_COMPUTE_UNITS = 12_345;

    address internal owner = makeAddr("owner");
    address internal developer = makeAddr("developer");
    address internal provider = makeAddr("provider");
    address internal tee = makeAddr("tee-cvm-key");
    address internal sponsor = makeAddr("sponsor");
    address internal stranger = makeAddr("stranger");
    address internal user;
    address internal verifier;
    address internal qvlVerifier;

    ComputeCreditVault internal vault;
    ConfigurableCreditERC20 internal token;
    mapping(bytes32 jobId => uint256 startedAt) internal startedAtByJob;

    function setUp() public virtual {
        user = vm.addr(USER_KEY);
        verifier = vm.addr(VERIFIER_KEY);
        qvlVerifier = vm.addr(QVL_KEY);
        vault = new ComputeCreditVault(owner, developer, 500);
        token = new ConfigurableCreditERC20();
        _configure(vault, address(token), owner, tee, provider, verifier);

        vm.deal(sponsor, 1_000 ether);
        vm.deal(user, 10 ether);
        token.mint(sponsor, 1_000_000 ether);
        vm.prank(sponsor);
        token.approve(address(vault), type(uint256).max);
    }

    function _configure(
        ComputeCreditVault target,
        address configuredAsset,
        address configurationOwner,
        address configuredTee,
        address configuredProvider,
        address configuredVerifier
    ) internal {
        vm.startPrank(configurationOwner);
        target.freezeDeveloperFee();
        target.proposeAsset(configuredAsset);
        target.proposeComposeHash(COMPOSE_HASH);
        target.proposeRatePolicy(NATIVE_POLICY, address(0), configuredProvider, 500);
        target.proposeMeteringBinding(configuredVerifier, qvlVerifier, METERING_POLICY_SET_HASH);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(configurationOwner);
        target.activateAsset(configuredAsset);
        target.activateComposeHash(COMPOSE_HASH);
        target.activateRatePolicy(NATIVE_POLICY);
        target.activateMeteringBinding();
        target.freezeMeteringBinding();
        target.proposeRatePolicy(TOKEN_POLICY, configuredAsset, configuredProvider, 500);
        target.proposeTeeIdentity(configuredTee, COMPOSE_HASH);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(configurationOwner);
        target.activateRatePolicy(TOKEN_POLICY);
        target.activateTeeIdentity(configuredTee);
        target.freezeAssetAdditions();
        target.freezeRatePolicyAdditions();
        target.freezeComposePolicy();
        target.freezeTeeIdentityAdditions();
        target.setPaused(false);
        vm.stopPrank();
    }

    function _fundNative(uint256 amount) internal {
        vm.prank(sponsor);
        vault.fundNative{value: amount}(PROJECT, user);
    }

    function _fundToken(uint256 amount) internal {
        vm.prank(sponsor);
        vault.fundERC20(PROJECT, user, address(token), amount);
    }

    function _authorization(bytes32 jobId, address asset, uint256 cap, bytes32 policy)
        internal
        view
        returns (ComputeCreditVault.JobAuthorization memory authorization)
    {
        authorization = ComputeCreditVault.JobAuthorization({
            projectId: PROJECT,
            jobId: jobId,
            user: user,
            asset: asset,
            nonce: vault.nextAuthorizationNonce(PROJECT, user),
            maxAssetDebit: cap,
            expiry: block.timestamp + 1 days,
            ratePolicyCommitment: policy,
            workloadCommitment: WORKLOAD,
            manifestCommitment: MANIFEST,
            dispatchIntentCommitment: DISPATCH_INTENT
        });
    }

    function _signAuthorization(ComputeCreditVault target, ComputeCreditVault.JobAuthorization memory authorization)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_KEY, target.jobAuthorizationDigest(authorization));
        return abi.encodePacked(r, s, v);
    }

    function _authorize(ComputeCreditVault.JobAuthorization memory authorization) internal {
        vault.authorizeJob(authorization, _signAuthorization(vault, authorization));
    }

    function _signMeterReceipt(
        ComputeCreditVault target,
        bytes32 jobId,
        uint256 debit,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry
    ) internal view returns (bytes memory) {
        bytes32 digest = target.meteringReceiptDigest(
            jobId, debit, billableComputeUnits, usageStartedAt, usageEndedAt, attestationEvidenceHash, receiptExpiry
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signQvlReceipt(
        ComputeCreditVault target,
        bytes32 jobId,
        uint256 debit,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry
    ) internal view returns (bytes memory) {
        bytes32 digest = target.meteringQvlReceiptDigest(
            jobId, debit, billableComputeUnits, usageStartedAt, usageEndedAt, attestationEvidenceHash, receiptExpiry
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(QVL_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signDefaultReceipts(
        ComputeCreditVault target,
        bytes32 jobId,
        uint256 debit,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry
    ) internal view returns (bytes memory meterSignature, bytes memory qvlSignature) {
        ComputeCreditVault.Job memory job = target.getJob(jobId);
        meterSignature = _signMeterReceipt(
            target,
            jobId,
            debit,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            attestationEvidenceHash,
            receiptExpiry
        );
        qvlSignature = _signQvlReceipt(
            target,
            jobId,
            debit,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            attestationEvidenceHash,
            receiptExpiry
        );
    }

    function _variantReceiptDigest(
        ComputeCreditVault target,
        bytes32 receiptTypehash,
        MeteredTerms memory terms,
        ExactExecutionCommitments memory commitments
    ) internal view returns (bytes32) {
        ComputeCreditVault.Job memory job = target.getJob(terms.jobId);
        bytes32 usageCommitment = keccak256(
            abi.encode(
                target.USAGE_COMMITMENT_TYPEHASH(),
                block.chainid,
                address(target),
                job.projectId,
                terms.jobId,
                job.user,
                job.asset,
                job.authorizationNonce,
                job.maxAssetDebit,
                terms.actualAssetDebit,
                uint256(job.authorizationExpiry),
                job.ratePolicyCommitment,
                commitments.workload,
                commitments.manifest,
                commitments.dispatchIntent,
                job.teeIdentity,
                job.composeHash,
                job.startCommitment,
                terms.billableComputeUnits,
                terms.usageStartedAt,
                terms.usageEndedAt,
                target.meteringPolicySetHash(),
                terms.attestationEvidenceHash
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                receiptTypehash,
                job.projectId,
                terms.jobId,
                job.user,
                job.asset,
                job.authorizationNonce,
                job.maxAssetDebit,
                terms.actualAssetDebit,
                uint256(job.authorizationExpiry),
                job.ratePolicyCommitment,
                commitments.workload,
                commitments.manifest,
                commitments.dispatchIntent,
                job.teeIdentity,
                job.composeHash,
                job.startCommitment,
                terms.billableComputeUnits,
                terms.usageStartedAt,
                terms.usageEndedAt,
                usageCommitment,
                target.meteringPolicySetHash(),
                terms.attestationEvidenceHash,
                terms.receiptExpiry
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", target.domainSeparator(), structHash));
    }

    function _signVariantReceipt(
        uint256 signerKey,
        ComputeCreditVault target,
        bytes32 receiptTypehash,
        MeteredTerms memory terms,
        ExactExecutionCommitments memory commitments
    ) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            signerKey, _variantReceiptDigest(target, receiptTypehash, terms, commitments)
        );
        return abi.encodePacked(r, s, v);
    }

    function _assertCommitmentVariantRejected(
        ComputeCreditVault target,
        MeteredTerms memory terms,
        ExactExecutionCommitments memory variant
    ) internal {
        ComputeCreditVault.Job memory job = target.getJob(terms.jobId);
        ExactExecutionCommitments memory exact = ExactExecutionCommitments({
            workload: job.workloadCommitment,
            manifest: job.manifestCommitment,
            dispatchIntent: job.dispatchIntentCommitment
        });
        bytes memory validMeter =
            _signVariantReceipt(VERIFIER_KEY, target, target.METERING_RECEIPT_TYPEHASH(), terms, exact);
        bytes memory validQvl =
            _signVariantReceipt(QVL_KEY, target, target.METERING_QVL_RECEIPT_TYPEHASH(), terms, exact);
        bytes memory wrongMeter =
            _signVariantReceipt(VERIFIER_KEY, target, target.METERING_RECEIPT_TYPEHASH(), terms, variant);
        bytes memory wrongQvl =
            _signVariantReceipt(QVL_KEY, target, target.METERING_QVL_RECEIPT_TYPEHASH(), terms, variant);

        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        vm.prank(tee);
        target.submitMeteringReceipt(
            terms.jobId,
            terms.actualAssetDebit,
            COMPOSE_HASH,
            terms.billableComputeUnits,
            terms.usageStartedAt,
            terms.usageEndedAt,
            terms.attestationEvidenceHash,
            terms.receiptExpiry,
            wrongMeter,
            validQvl
        );

        vm.expectRevert(ComputeCreditVault.InvalidMeteringQvlSignature.selector);
        vm.prank(tee);
        target.submitMeteringReceipt(
            terms.jobId,
            terms.actualAssetDebit,
            COMPOSE_HASH,
            terms.billableComputeUnits,
            terms.usageStartedAt,
            terms.usageEndedAt,
            terms.attestationEvidenceHash,
            terms.receiptExpiry,
            validMeter,
            wrongQvl
        );
    }

    function _submitDefaultReceipt(
        ComputeCreditVault target,
        bytes32 jobId,
        uint256 debit,
        bytes32 composeHash,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry,
        bytes memory meterSignature,
        bytes memory qvlSignature
    ) internal {
        target.submitMeteringReceipt(
            jobId,
            debit,
            composeHash,
            BILLABLE_COMPUTE_UNITS,
            startedAtByJob[jobId],
            block.timestamp,
            attestationEvidenceHash,
            receiptExpiry,
            meterSignature,
            qvlSignature
        );
    }

    function _settle(bytes32 jobId, uint256 debit) internal {
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        if (job.state == ComputeCreditVault.JobState.Authorized) {
            _start(jobId);
            job = vault.getJob(jobId);
        }
        uint256 usageStartedAt = job.startedAt;
        uint256 usageEndedAt = block.timestamp;
        uint256 receiptExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        bytes memory signature = _signMeterReceipt(
            vault,
            jobId,
            debit,
            BILLABLE_COMPUTE_UNITS,
            usageStartedAt,
            usageEndedAt,
            ATTESTATION_EVIDENCE,
            receiptExpiry
        );
        bytes memory qvlSignature = _signQvlReceipt(
            vault,
            jobId,
            debit,
            BILLABLE_COMPUTE_UNITS,
            usageStartedAt,
            usageEndedAt,
            ATTESTATION_EVIDENCE,
            receiptExpiry
        );
        vm.prank(tee);
        vault.submitMeteringReceipt(
            jobId,
            debit,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            usageStartedAt,
            usageEndedAt,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            signature,
            qvlSignature
        );
        assertTrue(receiptExpiry <= job.authorizationExpiry);
    }

    function _start(bytes32 jobId) internal {
        vm.prank(tee);
        vault.startJob(jobId, COMPOSE_HASH);
        startedAtByJob[jobId] = vault.getJob(jobId).startedAt;
    }

    function _assertCredit(address asset, uint256 available, uint256 reserved) internal view {
        (uint256 actualAvailable, uint256 actualReserved) = vault.credits(PROJECT, user, asset);
        assertEq(actualAvailable, available);
        assertEq(actualReserved, reserved);
    }
}

contract ComputeCreditVaultTest is ComputeCreditVaultFixture {
    function test_ConstructorAndDomainAreExplicit() public view {
        assertEq(vault.owner(), owner);
        assertEq(vault.developer(), developer);
        assertEq(vault.meteringVerifier(), verifier);
        assertEq(vault.meteringQvlVerifier(), qvlVerifier);
        assertEq(vault.developerFeeBps(), 500);
        assertTrue(vault.composePolicyFrozen());
        assertTrue(vault.teeIdentityAdditionsFrozen());
        assertTrue(vault.meteringBindingFrozen());
        assertEq(vault.meteringPolicySetHash(), METERING_POLICY_SET_HASH);
        assertFalse(vault.paused());
        bytes32 expected = keccak256(
            abi.encode(
                vault.EIP712_DOMAIN_TYPEHASH(), vault.NAME_HASH(), vault.VERSION_HASH(), block.chainid, address(vault)
            )
        );
        assertEq(vault.domainSeparator(), expected);
        assertEq(
            vault.METERING_RECEIPT_TYPEHASH(),
            keccak256(
                "ComputeMeteringReceipt(bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 usageCommitment,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash,uint256 receiptExpiry)"
            )
        );
        assertEq(
            vault.METERING_QVL_RECEIPT_TYPEHASH(),
            keccak256(
                "ComputeMeteringQvlReceipt(bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 usageCommitment,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash,uint256 receiptExpiry)"
            )
        );
    }

    function test_ConstructorRejectsInvalidRolesAndFee() public {
        vm.expectRevert(ComputeCreditVault.ZeroAddress.selector);
        new ComputeCreditVault(address(0), developer, 500);

        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        new ComputeCreditVault(owner, owner, 500);

        vm.expectRevert(ComputeCreditVault.ZeroAddress.selector);
        new ComputeCreditVault(owner, address(0), 500);

        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        new ComputeCreditVault(predicted, developer, 500);

        predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        new ComputeCreditVault(owner, predicted, 500);

        vm.expectRevert(ComputeCreditVault.FeeTooHigh.selector);
        new ComputeCreditVault(owner, developer, 2001);
    }

    function test_MeteringBindingIsTimelockedCancelableAndPermanentlyFreezeable() public {
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        bytes32 policySetHash = keccak256("metering-policy-set-v1");

        assertTrue(target.paused());
        assertEq(target.meteringVerifier(), address(0));
        assertEq(target.meteringQvlVerifier(), address(0));
        assertEq(target.meteringPolicySetHash(), bytes32(0));
        vm.startPrank(owner);
        target.proposeMeteringBinding(verifier, qvlVerifier, policySetHash);
        assertEq(target.pendingMeteringVerifier(), verifier);
        assertEq(target.pendingMeteringQvlVerifier(), qvlVerifier);
        assertEq(target.pendingMeteringPolicySetHash(), policySetHash);
        assertGt(target.pendingMeteringBindingActivatesAt(), block.timestamp);
        vm.expectRevert(ComputeCreditVault.PendingAdmissions.selector);
        target.freezeMeteringBinding();
        vm.expectPartialRevert(ComputeCreditVault.TimelockNotElapsed.selector);
        target.activateMeteringBinding();
        target.cancelMeteringBindingProposal();
        assertEq(target.pendingMeteringVerifier(), address(0));
        assertEq(target.pendingMeteringQvlVerifier(), address(0));
        assertEq(target.pendingMeteringPolicySetHash(), bytes32(0));
        assertEq(target.pendingMeteringBindingActivatesAt(), 0);
        target.proposeMeteringBinding(verifier, qvlVerifier, policySetHash);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateMeteringBinding();
        assertEq(target.meteringVerifier(), verifier);
        assertEq(target.meteringQvlVerifier(), qvlVerifier);
        assertEq(target.meteringPolicySetHash(), policySetHash);
        assertTrue(target.meteringVerifierEverConfigured(verifier));
        assertTrue(target.meteringQvlVerifierEverConfigured(qvlVerifier));
        target.freezeMeteringBinding();
        assertTrue(target.meteringBindingFrozen());
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeMeteringBinding(
            makeAddr("replacement-meter"), makeAddr("replacement-qvl"), keccak256("replacement-policy")
        );
        vm.stopPrank();
    }

    function test_MeteringRolesMustBeNonzeroDistinctAndIndependentlyFrozen() public {
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        vm.startPrank(owner);
        vm.expectRevert(ComputeCreditVault.ZeroAddress.selector);
        target.proposeMeteringBinding(verifier, address(0), METERING_POLICY_SET_HASH);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeMeteringBinding(verifier, verifier, METERING_POLICY_SET_HASH);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeMeteringBinding(owner, qvlVerifier, METERING_POLICY_SET_HASH);
        vm.stopPrank();
    }

    function test_ServiceRoleHistoriesCannotCrossRolesOrOwnTheVault() public {
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        bytes32 policy = keccak256("history-provider-policy");
        vm.startPrank(owner);
        target.freezeDeveloperFee();
        target.proposeRatePolicy(policy, address(0), provider, 500);
        target.proposeComposeHash(COMPOSE_HASH);
        target.proposeMeteringBinding(verifier, qvlVerifier, METERING_POLICY_SET_HASH);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateRatePolicy(policy);
        target.activateComposeHash(COMPOSE_HASH);
        target.activateMeteringBinding();
        target.proposeTeeIdentity(tee, COMPOSE_HASH);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateTeeIdentity(tee);
        target.revokeTeeIdentity(tee);

        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.transferOwnership(address(target));
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.transferOwnership(provider);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.transferOwnership(verifier);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.transferOwnership(qvlVerifier);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.transferOwnership(tee);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeMeteringBinding(provider, qvlVerifier, keccak256("provider-as-meter"));
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeMeteringBinding(tee, qvlVerifier, keccak256("historical-tee-as-meter"));
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeMeteringBinding(qvlVerifier, makeAddr("new-qvl"), keccak256("qvl-history-as-meter"));
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeMeteringBinding(makeAddr("new-meter"), verifier, keccak256("meter-history-as-qvl"));
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeTeeIdentity(verifier, COMPOSE_HASH);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeTeeIdentity(qvlVerifier, COMPOSE_HASH);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeRatePolicy(keccak256("meter-as-provider"), address(0), verifier, 500);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeRatePolicy(keccak256("qvl-as-provider"), address(0), qvlVerifier, 500);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeRatePolicy(keccak256("tee-as-provider"), address(0), tee, 500);
        vm.stopPrank();
    }

    function test_OwnershipIsTwoStepAndSeparatedFromServiceRoles() public {
        address nextOwner = makeAddr("next-owner");
        vm.prank(owner);
        vault.transferOwnership(nextOwner);

        vm.prank(stranger);
        vm.expectRevert(ComputeCreditVault.NotPendingOwner.selector);
        vault.acceptOwnership();

        vm.prank(nextOwner);
        vault.acceptOwnership();
        assertEq(vault.owner(), nextOwner);

        vm.startPrank(nextOwner);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        vault.transferOwnership(developer);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        vault.transferOwnership(verifier);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        vault.transferOwnership(qvlVerifier);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        vault.transferOwnership(provider);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        vault.transferOwnership(tee);
        vm.stopPrank();
    }

    function test_PendingOwnerCannotGainServiceRoleDuringTransferWindow() public {
        address candidate = makeAddr("ownership-candidate");
        bytes32 stagedPolicy = keccak256("staged-owner-policy");
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);

        // Stage a provider policy before beginning ownership transfer. The
        // activation-time check must catch the new pending-owner conflict.
        vm.startPrank(owner);
        target.freezeDeveloperFee();
        target.proposeRatePolicy(stagedPolicy, address(0), candidate, 500);
        target.transferOwnership(candidate);
        vm.stopPrank();

        vm.startPrank(owner);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeRatePolicy(keccak256("pending-owner-provider"), address(0), candidate, 500);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeTeeIdentity(candidate, COMPOSE_HASH);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        vm.prank(owner);
        target.activateRatePolicy(stagedPolicy);
    }

    function test_AcceptOwnershipRechecksServiceRolesAtAcceptance() public {
        address candidate = makeAddr("accept-time-candidate");
        ComputeCreditVaultRoleHarness target = new ComputeCreditVaultRoleHarness(owner, developer, 500);
        vm.prank(owner);
        target.transferOwnership(candidate);
        target.forceProviderRole(candidate);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        vm.prank(candidate);
        target.acceptOwnership();
        assertEq(target.owner(), owner);
        assertEq(target.pendingOwner(), candidate);
    }

    function test_NonOwnerCannotGovern() public {
        vm.startPrank(stranger);
        vm.expectRevert(ComputeCreditVault.NotOwner.selector);
        vault.setPaused(true);
        vm.expectRevert(ComputeCreditVault.NotOwner.selector);
        vault.proposeAsset(address(token));
        vm.expectRevert(ComputeCreditVault.NotOwner.selector);
        vault.revokeRatePolicy(NATIVE_POLICY);
        vm.expectRevert(ComputeCreditVault.NotOwner.selector);
        vault.revokeTeeIdentity(tee);
        vm.stopPrank();
    }

    function test_GovernanceIsTimelockedFreezeableAndImmediatelyRevocable() public {
        ConfigurableCreditERC20 second = new ConfigurableCreditERC20();
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        bytes32 secondCompose = keccak256("second-compose");
        bytes32 secondPolicy = keccak256("second-policy");

        assertEq(target.allowedAssetCount(), 0);
        assertEq(target.activeRatePolicyCount(), 0);

        vm.startPrank(owner);
        target.proposeDeveloperFee(700);
        target.proposeAsset(address(second));
        target.proposeComposeHash(secondCompose);
        vm.expectPartialRevert(ComputeCreditVault.TimelockNotElapsed.selector);
        target.activateDeveloperFee();
        vm.expectPartialRevert(ComputeCreditVault.TimelockNotElapsed.selector);
        target.activateAsset(address(second));
        vm.expectPartialRevert(ComputeCreditVault.TimelockNotElapsed.selector);
        target.activateComposeHash(secondCompose);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateDeveloperFee();
        target.activateAsset(address(second));
        target.activateComposeHash(secondCompose);
        assertEq(target.allowedAssetCount(), 1);
        target.freezeDeveloperFee();
        target.proposeRatePolicy(secondPolicy, address(second), makeAddr("provider-2"), 700);
        vm.expectPartialRevert(ComputeCreditVault.TimelockNotElapsed.selector);
        target.activateRatePolicy(secondPolicy);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateRatePolicy(secondPolicy);
        assertEq(target.activeRatePolicyCount(), 1);
        target.freezeAssetAdditions();
        target.freezeRatePolicyAdditions();
        target.freezeComposePolicy();
        target.revokeAsset(address(second));
        target.revokeRatePolicy(secondPolicy);
        target.revokeComposeHash(secondCompose);
        assertEq(target.allowedAssetCount(), 0);
        assertEq(target.activeRatePolicyCount(), 0);

        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeDeveloperFee(800);
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeAsset(address(second));
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeRatePolicy(keccak256("never"), address(0), makeAddr("provider-3"), 700);
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeComposeHash(keccak256("never-compose"));
        vm.stopPrank();
    }

    function test_EveryGovernanceProposalCanBeCancelledBeforeActivation() public {
        ConfigurableCreditERC20 second = new ConfigurableCreditERC20();
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        ComputeCreditVault rateTarget = new ComputeCreditVault(owner, developer, 500);
        bytes32 cancelledCompose = keccak256("cancelled-compose");
        bytes32 cancelledPolicy = keccak256("cancelled-rate-policy");
        bytes32 cancelledMeteringPolicy = keccak256("cancelled-metering-policy");
        vm.startPrank(owner);
        target.proposeDeveloperFee(600);
        target.proposeAsset(address(second));
        target.proposeComposeHash(cancelledCompose);
        target.proposeMeteringBinding(verifier, qvlVerifier, cancelledMeteringPolicy);
        rateTarget.freezeDeveloperFee();
        rateTarget.proposeRatePolicy(cancelledPolicy, address(0), makeAddr("cancelled-provider"), 500);
        assertEq(target.pendingAssetCount(), 1);
        assertEq(rateTarget.pendingRatePolicyCount(), 1);
        assertEq(target.pendingComposeCount(), 1);
        target.cancelDeveloperFeeProposal();
        target.cancelAssetProposal(address(second));
        target.cancelComposeHashProposal(cancelledCompose);
        rateTarget.cancelRatePolicyProposal(cancelledPolicy);
        target.cancelMeteringBindingProposal();
        assertEq(target.pendingAssetCount(), 0);
        assertEq(rateTarget.pendingRatePolicyCount(), 0);
        assertEq(target.pendingComposeCount(), 0);
        assertEq(target.pendingMeteringBindingActivatesAt(), 0);

        vm.expectRevert(ComputeCreditVault.ProposalMissing.selector);
        target.activateDeveloperFee();
        vm.expectRevert(ComputeCreditVault.ProposalMissing.selector);
        target.activateAsset(address(second));
        vm.expectRevert(ComputeCreditVault.ProposalMissing.selector);
        target.activateComposeHash(cancelledCompose);
        vm.expectRevert(ComputeCreditVault.ProposalMissing.selector);
        rateTarget.activateRatePolicy(cancelledPolicy);
        vm.expectRevert(ComputeCreditVault.ProposalMissing.selector);
        target.activateMeteringBinding();
        vm.stopPrank();
    }

    function test_AdmissionCountersTrackPendingAndTeeRevocationExactly() public {
        ConfigurableCreditERC20 second = new ConfigurableCreditERC20();
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        bytes32 pendingCompose = keccak256("counter-compose");
        bytes32 pendingPolicy = keccak256("counter-policy");
        address secondTee = makeAddr("counter-tee");

        assertEq(target.pendingAssetCount(), 0);
        assertEq(target.pendingRatePolicyCount(), 0);
        assertEq(target.pendingComposeCount(), 0);
        assertEq(target.pendingTeeIdentityCount(), 0);
        assertEq(target.approvedTeeIdentityCount(), 0);

        vm.startPrank(owner);
        target.freezeDeveloperFee();
        target.proposeAsset(address(second));
        target.proposeRatePolicy(pendingPolicy, address(0), makeAddr("counter-provider"), 500);
        target.proposeComposeHash(pendingCompose);
        assertEq(target.pendingAssetCount(), 1);
        assertEq(target.pendingRatePolicyCount(), 1);
        assertEq(target.pendingComposeCount(), 1);

        target.cancelAssetProposal(address(second));
        target.cancelRatePolicyProposal(pendingPolicy);
        target.cancelComposeHashProposal(pendingCompose);
        assertEq(target.pendingAssetCount(), 0);
        assertEq(target.pendingRatePolicyCount(), 0);
        assertEq(target.pendingComposeCount(), 0);
        target.proposeComposeHash(COMPOSE_HASH);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateComposeHash(COMPOSE_HASH);
        target.proposeTeeIdentity(secondTee, COMPOSE_HASH);
        assertEq(target.pendingTeeIdentityCount(), 1);
        vm.expectRevert(ComputeCreditVault.ProposalExists.selector);
        target.proposeTeeIdentity(secondTee, COMPOSE_HASH);
        target.cancelTeeIdentityProposal(secondTee);
        assertEq(target.pendingTeeIdentityCount(), 0);
        target.proposeTeeIdentity(secondTee, COMPOSE_HASH);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateTeeIdentity(secondTee);
        assertEq(target.pendingTeeIdentityCount(), 0);
        assertEq(target.approvedTeeIdentityCount(), 1);
        assertTrue(target.teeIdentityEverApproved(secondTee));
        target.revokeTeeIdentity(secondTee);
        assertEq(target.approvedTeeIdentityCount(), 0);
        vm.stopPrank();
    }

    function test_AdmissionFreezesRejectHiddenPendingProposals() public {
        ConfigurableCreditERC20 second = new ConfigurableCreditERC20();
        ComputeCreditVault assetRateTarget = new ComputeCreditVault(owner, developer, 500);
        bytes32 pendingPolicy = keccak256("freeze-pending-policy");
        vm.startPrank(owner);
        assetRateTarget.freezeDeveloperFee();
        assetRateTarget.proposeAsset(address(second));
        vm.expectRevert(ComputeCreditVault.PendingAdmissions.selector);
        assetRateTarget.freezeAssetAdditions();
        assetRateTarget.cancelAssetProposal(address(second));
        assetRateTarget.freezeAssetAdditions();

        assetRateTarget.proposeRatePolicy(pendingPolicy, address(0), makeAddr("freeze-pending-provider"), 500);
        vm.expectRevert(ComputeCreditVault.PendingAdmissions.selector);
        assetRateTarget.freezeRatePolicyAdditions();
        assetRateTarget.cancelRatePolicyProposal(pendingPolicy);
        assetRateTarget.freezeRatePolicyAdditions();
        vm.stopPrank();

        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        bytes32 approved = keccak256("freeze-approved-compose");
        bytes32 pending = keccak256("freeze-pending-compose");
        vm.startPrank(owner);
        target.proposeComposeHash(approved);
        target.proposeComposeHash(pending);
        vm.stopPrank();
        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateComposeHash(approved);
        vm.expectRevert(ComputeCreditVault.PendingAdmissions.selector);
        target.freezeComposePolicy();
        target.cancelComposeHashProposal(pending);
        target.freezeComposePolicy();
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeComposeHash(keccak256("post-freeze-compose"));

        target.proposeTeeIdentity(tee, approved);
        vm.expectRevert(ComputeCreditVault.PendingAdmissions.selector);
        target.freezeTeeIdentityAdditions();
        target.cancelTeeIdentityProposal(tee);
        target.proposeTeeIdentity(tee, approved);
        vm.stopPrank();

        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateTeeIdentity(tee);
        target.freezeTeeIdentityAdditions();
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeTeeIdentity(makeAddr("post-freeze-tee"), approved);
        vm.stopPrank();
    }

    function test_RatePolicyActivationRechecksRoleAndFeeMustFreezeBeforeProposal() public {
        address candidate = makeAddr("toctou-provider");
        bytes32 rolePolicy = keccak256("toctou-role-policy");
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        vm.startPrank(owner);
        target.freezeDeveloperFee();
        target.proposeRatePolicy(rolePolicy, address(0), candidate, 500);
        target.proposeComposeHash(COMPOSE_HASH);
        vm.stopPrank();
        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateComposeHash(COMPOSE_HASH);
        target.proposeTeeIdentity(candidate, COMPOSE_HASH);
        vm.stopPrank();
        vm.warp(block.timestamp + target.GOVERNANCE_TIMELOCK());
        vm.startPrank(owner);
        target.activateTeeIdentity(candidate);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.activateRatePolicy(rolePolicy);
        target.revokeTeeIdentity(candidate);
        vm.expectRevert(ComputeCreditVault.RoleConflict.selector);
        target.proposeRatePolicy(keccak256("historical-tee-provider"), address(0), candidate, 500);
        vm.stopPrank();

        vm.prank(owner);
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        target.proposeDeveloperFee(600);
    }

    function test_SponsorFundsNativeAndTokenOnBehalfWithoutMintingTransferableToken() public {
        _fundNative(3 ether);
        _fundToken(900 ether);

        _assertCredit(address(0), 3 ether, 0);
        _assertCredit(address(token), 900 ether, 0);
        assertEq(vault.totalLiability(address(0)), 3 ether);
        assertEq(vault.totalLiability(address(token)), 900 ether);
        assertEq(address(vault).balance, 3 ether);
        assertEq(token.balanceOf(address(vault)), 900 ether);
        assertEq(vault.surplus(address(0)), 0);
        assertEq(vault.surplus(address(token)), 0);
    }

    function test_FundingRejectsBadInputsDirectCustodyAndDisallowedAsset() public {
        vm.startPrank(sponsor);
        vm.expectRevert(ComputeCreditVault.ZeroCommitment.selector);
        vault.fundNative{value: 1}(bytes32(0), user);
        vm.expectRevert(ComputeCreditVault.ZeroAddress.selector);
        vault.fundNative{value: 1}(PROJECT, address(0));
        vm.expectRevert(ComputeCreditVault.ZeroAmount.selector);
        vault.fundNative(PROJECT, user);

        ConfigurableCreditERC20 unknown = new ConfigurableCreditERC20();
        unknown.mint(sponsor, 100);
        unknown.approve(address(vault), 100);
        vm.expectRevert(ComputeCreditVault.AssetNotAllowed.selector);
        vault.fundERC20(PROJECT, user, address(unknown), 100);

        vm.expectRevert(ComputeCreditVault.DirectCustodyDisabled.selector);
        (bool sent,) = address(vault).call{value: 1}("");
        assertTrue(sent);
        vm.stopPrank();
    }

    function test_ExactTransferChecksRejectFeePhantomAndFalseReturnFunding() public {
        token.setBehavior(100, false, false);
        vm.prank(sponsor);
        vm.expectRevert(ComputeCreditVault.AssetAmountMismatch.selector);
        vault.fundERC20(PROJECT, user, address(token), 100 ether);

        token.setBehavior(0, true, false);
        vm.prank(sponsor);
        vm.expectRevert(ComputeCreditVault.AssetAmountMismatch.selector);
        vault.fundERC20(PROJECT, user, address(token), 100 ether);

        token.setBehavior(0, false, true);
        vm.prank(sponsor);
        vm.expectRevert(ComputeCreditVault.TransferFailed.selector);
        vault.fundERC20(PROJECT, user, address(token), 100 ether);
        assertEq(vault.totalLiability(address(token)), 0);
    }

    function test_AssetAdmissionRejectsEOAAndMalformedBalanceToken() public {
        ComputeCreditVault admissionTarget = new ComputeCreditVault(owner, developer, 500);
        vm.prank(owner);
        vm.expectRevert(ComputeCreditVault.InvalidAsset.selector);
        admissionTarget.proposeAsset(stranger);

        MalformedBalanceToken malformed = new MalformedBalanceToken();
        ComputeCreditVault malformedTarget = new ComputeCreditVault(owner, developer, 500);
        _configure(malformedTarget, address(malformed), owner, tee, provider, verifier);
        vm.prank(sponsor);
        vm.expectRevert(ComputeCreditVault.TransferFailed.selector);
        malformedTarget.fundERC20(PROJECT, user, address(malformed), 1);
    }

    function test_AuthorizationReservesExactCapAndConsumesSequentialNonce() public {
        _fundNative(5 ether);
        bytes32 jobId = keccak256("job-1");
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(jobId, address(0), 2 ether, NATIVE_POLICY);
        _authorize(authorization);

        _assertCredit(address(0), 3 ether, 2 ether);
        assertEq(vault.nextAuthorizationNonce(PROJECT, user), 1);
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        assertEq(job.projectId, PROJECT);
        assertEq(job.user, user);
        assertEq(job.maxAssetDebit, 2 ether);
        assertEq(uint8(job.state), uint8(ComputeCreditVault.JobState.Authorized));
    }

    function test_AuthorizationBindsExactNonzeroWorkloadManifestAndDispatchIntent() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("exact-execution-envelope");
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        bytes memory signature = _signAuthorization(vault, authorization);

        ComputeCreditVault.JobAuthorization memory changed = _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        changed.workloadCommitment = keccak256("other-workload");
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(changed, signature);

        changed = _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        changed.manifestCommitment = keccak256("other-manifest");
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(changed, signature);

        changed = _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        changed.dispatchIntentCommitment = keccak256("other-dispatch-intent");
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(changed, signature);

        changed = _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        changed.workloadCommitment = bytes32(0);
        bytes memory zeroWorkloadSignature = _signAuthorization(vault, changed);
        vm.expectRevert(ComputeCreditVault.ZeroCommitment.selector);
        vault.authorizeJob(changed, zeroWorkloadSignature);

        changed = _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        changed.manifestCommitment = bytes32(0);
        bytes memory zeroManifestSignature = _signAuthorization(vault, changed);
        vm.expectRevert(ComputeCreditVault.ZeroCommitment.selector);
        vault.authorizeJob(changed, zeroManifestSignature);

        changed = _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        changed.dispatchIntentCommitment = bytes32(0);
        bytes memory zeroDispatchSignature = _signAuthorization(vault, changed);
        vm.expectRevert(ComputeCreditVault.ZeroCommitment.selector);
        vault.authorizeJob(changed, zeroDispatchSignature);

        authorization = _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        vault.authorizeJob(authorization, signature);
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        assertEq(job.workloadCommitment, WORKLOAD);
        assertEq(job.manifestCommitment, MANIFEST);
        assertEq(job.dispatchIntentCommitment, DISPATCH_INTENT);
    }

    function test_AuthorizationRejectsReplayWrongNonceInsufficientCreditAndWrongPolicyAsset() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("replay-job");
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        bytes memory signature = _signAuthorization(vault, authorization);
        vault.authorizeJob(authorization, signature);

        vm.expectRevert(ComputeCreditVault.JobAlreadyExists.selector);
        vault.authorizeJob(authorization, signature);

        ComputeCreditVault.JobAuthorization memory wrongNonce =
            _authorization(keccak256("wrong-nonce"), address(0), 1, NATIVE_POLICY);
        wrongNonce.nonce = 99;
        bytes memory wrongNonceSignature = _signAuthorization(vault, wrongNonce);
        vm.expectPartialRevert(ComputeCreditVault.InvalidAuthorizationNonce.selector);
        vault.authorizeJob(wrongNonce, wrongNonceSignature);

        ComputeCreditVault.JobAuthorization memory tooLarge =
            _authorization(keccak256("too-large"), address(0), 2 ether, NATIVE_POLICY);
        bytes memory tooLargeSignature = _signAuthorization(vault, tooLarge);
        vm.expectRevert(ComputeCreditVault.InsufficientAvailableCredit.selector);
        vault.authorizeJob(tooLarge, tooLargeSignature);

        ComputeCreditVault.JobAuthorization memory wrongAsset =
            _authorization(keccak256("wrong-asset"), address(token), 1, NATIVE_POLICY);
        bytes memory wrongAssetSignature = _signAuthorization(vault, wrongAsset);
        vm.expectRevert(ComputeCreditVault.AssetNotAllowed.selector);
        vault.authorizeJob(wrongAsset, wrongAssetSignature);
    }

    function test_AuthorizationRejectsMalformedExpiredOverlongAndWrongSignerSignatures() public {
        _fundNative(2 ether);
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(keccak256("invalid-auth"), address(0), 1 ether, NATIVE_POLICY);

        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(authorization, hex"1234");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, vault.jobAuthorizationDigest(authorization));
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(authorization, abi.encodePacked(r, s, v));

        authorization.expiry = block.timestamp;
        bytes memory expiredSignature = _signAuthorization(vault, authorization);
        vm.expectRevert(ComputeCreditVault.InvalidAuthorizationExpiry.selector);
        vault.authorizeJob(authorization, expiredSignature);

        authorization.expiry = block.timestamp + vault.MAX_JOB_LIFETIME() + 1;
        bytes memory overlongSignature = _signAuthorization(vault, authorization);
        vm.expectRevert(ComputeCreditVault.InvalidAuthorizationExpiry.selector);
        vault.authorizeJob(authorization, overlongSignature);
    }

    function test_HighSMalleatedAuthorizationSignatureIsRejected() public {
        _fundNative(2 ether);
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(keccak256("malleability"), address(0), 1 ether, NATIVE_POLICY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_KEY, vault.jobAuthorizationDigest(authorization));
        bytes32 highS = bytes32(SECP256K1_FULL_ORDER - uint256(s));
        uint8 toggledV = v == 27 ? 28 : 27;

        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(authorization, abi.encodePacked(r, highS, toggledV));
    }

    function test_HighSMalleatedMeterAndQvlSignaturesAreRejected() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("metering-malleability");
        _authorize(_authorization(jobId, address(0), 1 ether, NATIVE_POLICY));
        _start(jobId);
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        uint256 receiptExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();

        bytes32 meterDigest = vault.meteringReceiptDigest(
            jobId, 1 ether, BILLABLE_COMPUTE_UNITS, job.startedAt, block.timestamp, ATTESTATION_EVIDENCE, receiptExpiry
        );
        (uint8 meterV, bytes32 meterR, bytes32 meterS) = vm.sign(VERIFIER_KEY, meterDigest);
        bytes memory highSMeterSignature = abi.encodePacked(
            meterR, bytes32(SECP256K1_FULL_ORDER - uint256(meterS)), meterV == 27 ? uint8(28) : uint8(27)
        );
        bytes memory validQvlSignature = _signQvlReceipt(
            vault,
            jobId,
            1 ether,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            receiptExpiry
        );
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vm.prank(tee);
        _submitDefaultReceipt(
            vault,
            jobId,
            1 ether,
            COMPOSE_HASH,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            highSMeterSignature,
            validQvlSignature
        );

        bytes32 qvlDigest = vault.meteringQvlReceiptDigest(
            jobId, 1 ether, BILLABLE_COMPUTE_UNITS, job.startedAt, block.timestamp, ATTESTATION_EVIDENCE, receiptExpiry
        );
        (uint8 qvlV, bytes32 qvlR, bytes32 qvlS) = vm.sign(QVL_KEY, qvlDigest);
        bytes memory highSQvlSignature =
            abi.encodePacked(qvlR, bytes32(SECP256K1_FULL_ORDER - uint256(qvlS)), qvlV == 27 ? uint8(28) : uint8(27));
        bytes memory validMeterSignature = _signMeterReceipt(
            vault,
            jobId,
            1 ether,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            receiptExpiry
        );
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vm.prank(tee);
        _submitDefaultReceipt(
            vault,
            jobId,
            1 ether,
            COMPOSE_HASH,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            validMeterSignature,
            highSQvlSignature
        );
    }

    function test_Erc1271SmartAccountCanAuthorizeAndInvalidContractSignatureFailsClosed() public {
        Mock1271Signer smartAccount = new Mock1271Signer();
        vm.prank(sponsor);
        vault.fundNative{value: 2 ether}(PROJECT, address(smartAccount));
        bytes memory walletSignature = hex"cafe";
        ComputeCreditVault.JobAuthorization memory authorization = ComputeCreditVault.JobAuthorization({
            projectId: PROJECT,
            jobId: keccak256("smart-account-job"),
            user: address(smartAccount),
            asset: address(0),
            nonce: 0,
            maxAssetDebit: 1 ether,
            expiry: block.timestamp + 1 days,
            ratePolicyCommitment: NATIVE_POLICY,
            workloadCommitment: WORKLOAD,
            manifestCommitment: MANIFEST,
            dispatchIntentCommitment: DISPATCH_INTENT
        });
        smartAccount.approve(vault.jobAuthorizationDigest(authorization), walletSignature);
        vault.authorizeJob(authorization, walletSignature);
        (uint256 available, uint256 reserved) = vault.credits(PROJECT, address(smartAccount), address(0));
        assertEq(available, 1 ether);
        assertEq(reserved, 1 ether);

        authorization.jobId = keccak256("smart-account-invalid-job");
        authorization.nonce = 1;
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(authorization, walletSignature);

        smartAccount.setShouldRevert(true);
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(authorization, walletSignature);
    }

    function test_Erc1271IndependentMeteringVerifierCanAuthorizeReceipt() public {
        Mock1271Signer contractVerifier = new Mock1271Signer();
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        ConfigurableCreditERC20 targetToken = new ConfigurableCreditERC20();
        _configure(target, address(targetToken), owner, tee, provider, address(contractVerifier));
        vm.prank(sponsor);
        target.fundNative{value: 2 ether}(PROJECT, user);

        bytes32 jobId = keccak256("smart-verifier-job");
        ComputeCreditVault.JobAuthorization memory authorization = ComputeCreditVault.JobAuthorization({
            projectId: PROJECT,
            jobId: jobId,
            user: user,
            asset: address(0),
            nonce: 0,
            maxAssetDebit: 1 ether,
            expiry: block.timestamp + 1 days,
            ratePolicyCommitment: NATIVE_POLICY,
            workloadCommitment: WORKLOAD,
            manifestCommitment: MANIFEST,
            dispatchIntentCommitment: DISPATCH_INTENT
        });
        target.authorizeJob(authorization, _signAuthorization(target, authorization));
        vm.prank(tee);
        target.startJob(jobId, COMPOSE_HASH);
        ComputeCreditVault.Job memory job = target.getJob(jobId);
        uint256 receiptExpiry = block.timestamp + target.MAX_METERING_RECEIPT_LIFETIME();
        bytes memory receiptSignature = hex"cafe";
        contractVerifier.approve(
            target.meteringReceiptDigest(
                jobId,
                0.5 ether,
                BILLABLE_COMPUTE_UNITS,
                job.startedAt,
                block.timestamp,
                ATTESTATION_EVIDENCE,
                receiptExpiry
            ),
            receiptSignature
        );
        bytes memory qvlSignature = _signQvlReceipt(
            target,
            jobId,
            0.5 ether,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            receiptExpiry
        );
        vm.prank(tee);
        target.submitMeteringReceipt(
            jobId,
            0.5 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            receiptSignature,
            qvlSignature
        );
        assertEq(target.claimableAccrual(address(0), provider), 0.475 ether);
    }

    function test_Eip712PreventsCrossContractAndCrossChainReplay() public {
        _fundNative(3 ether);
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(keccak256("domain-replay"), address(0), 1 ether, NATIVE_POLICY);
        authorization.expiry = block.timestamp + 10 days;
        bytes memory originalSignature = _signAuthorization(vault, authorization);

        ComputeCreditVault second = new ComputeCreditVault(owner, developer, 500);
        ConfigurableCreditERC20 secondToken = new ConfigurableCreditERC20();
        _configure(second, address(secondToken), owner, tee, provider, verifier);
        vm.prank(sponsor);
        second.fundNative{value: 1 ether}(PROJECT, user);
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        second.authorizeJob(authorization, originalSignature);

        uint256 originalChain = block.chainid;
        vm.chainId(originalChain + 1);
        vm.expectRevert(ComputeCreditVault.InvalidSignature.selector);
        vault.authorizeJob(authorization, originalSignature);
        vm.chainId(originalChain);
    }

    function test_UserCanInvalidateNonceAndOldAuthorizationCannotReplay() public {
        _fundNative(1 ether);
        ComputeCreditVault.JobAuthorization memory oldAuthorization =
            _authorization(keccak256("old-nonce"), address(0), 1, NATIVE_POLICY);
        bytes memory oldSignature = _signAuthorization(vault, oldAuthorization);

        vm.prank(user);
        vault.invalidateAuthorizationNonce(PROJECT, 5);
        assertEq(vault.nextAuthorizationNonce(PROJECT, user), 5);
        vm.expectPartialRevert(ComputeCreditVault.InvalidAuthorizationNonce.selector);
        vault.authorizeJob(oldAuthorization, oldSignature);

        vm.expectPartialRevert(ComputeCreditVault.InvalidAuthorizationNonce.selector);
        vm.prank(user);
        vault.invalidateAuthorizationNonce(PROJECT, 5);
    }

    function test_CancelAndPermissionlessExpiryReleaseFullReservation() public {
        _fundNative(5 ether);
        ComputeCreditVault.JobAuthorization memory first =
            _authorization(keccak256("cancel"), address(0), 2 ether, NATIVE_POLICY);
        _authorize(first);

        vm.prank(stranger);
        vm.expectRevert(ComputeCreditVault.NotJobUser.selector);
        vault.cancelJob(first.jobId);
        vm.prank(user);
        vault.cancelJob(first.jobId);
        _assertCredit(address(0), 5 ether, 0);

        ComputeCreditVault.JobAuthorization memory second =
            _authorization(keccak256("expire"), address(0), 3 ether, NATIVE_POLICY);
        second.expiry = block.timestamp + 2 hours;
        _authorize(second);
        vm.expectRevert(ComputeCreditVault.InvalidAuthorizationExpiry.selector);
        vault.expireJob(second.jobId);
        vm.warp(second.expiry + 1);
        vm.prank(stranger);
        vault.expireJob(second.jobId);
        _assertCredit(address(0), 5 ether, 0);
    }

    function test_MeteringDebitsActualSplitsAccrualAndReleasesUnused() public {
        _fundNative(10 ether);
        bytes32 jobId = keccak256("metered-native");
        _authorize(_authorization(jobId, address(0), 8 ether, NATIVE_POLICY));
        _settle(jobId, 3 ether);

        _assertCredit(address(0), 7 ether, 0);
        assertEq(vault.claimableAccrual(address(0), provider), 2.85 ether);
        assertEq(vault.claimableAccrual(address(0), developer), 0.15 ether);
        assertEq(vault.totalLiability(address(0)), 10 ether);
        assertEq(address(vault).balance, 10 ether);

        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        assertEq(job.actualAssetDebit, 3 ether);
        assertEq(job.composeHash, COMPOSE_HASH);
        assertEq(job.workloadCommitment, WORKLOAD);
        assertEq(job.manifestCommitment, MANIFEST);
        assertEq(job.dispatchIntentCommitment, DISPATCH_INTENT);
        assertEq(job.billableComputeUnits, BILLABLE_COMPUTE_UNITS);
        assertEq(job.attestationEvidenceHash, ATTESTATION_EVIDENCE);
        assertEq(
            job.usageCommitment,
            vault.usageCommitmentFor(
                jobId, 3 ether, BILLABLE_COMPUTE_UNITS, job.startedAt, job.usageEndedAt, ATTESTATION_EVIDENCE
            )
        );
        assertEq(job.teeIdentity, tee);
        assertEq(uint8(job.state), uint8(ComputeCreditVault.JobState.Settled));
    }

    function test_ZeroDebitReceiptIsValidAndReturnsEntireCap() public {
        _fundNative(1 ether);
        bytes32 jobId = keccak256("zero-debit");
        _authorize(_authorization(jobId, address(0), 1 ether, NATIVE_POLICY));
        _settle(jobId, 0);
        _assertCredit(address(0), 1 ether, 0);
        assertEq(vault.claimableAccrual(address(0), provider), 0);
    }

    function test_MeteringRejectsCapExceededReplayBadReceiptAndWrongSigner() public {
        _fundNative(5 ether);
        bytes32 jobId = keccak256("bad-metering");
        _authorize(_authorization(jobId, address(0), 2 ether, NATIVE_POLICY));
        _start(jobId);
        uint256 expiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        (bytes memory overCap, bytes memory overCapQvl) =
            _signDefaultReceipts(vault, jobId, 3 ether, ATTESTATION_EVIDENCE, expiry);
        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.DebitExceedsJobCap.selector);
        _submitDefaultReceipt(vault, jobId, 3 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, overCap, overCapQvl);

        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            0xBAD,
            vault.meteringReceiptDigest(
                jobId, 1 ether, BILLABLE_COMPUTE_UNITS, job.startedAt, block.timestamp, ATTESTATION_EVIDENCE, expiry
            )
        );
        (, bytes memory qvlSignature) = _signDefaultReceipts(vault, jobId, 1 ether, ATTESTATION_EVIDENCE, expiry);
        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        _submitDefaultReceipt(
            vault, jobId, 1 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, abi.encodePacked(r, s, v), qvlSignature
        );

        (bytes memory valid, bytes memory validQvl) =
            _signDefaultReceipts(vault, jobId, 1 ether, ATTESTATION_EVIDENCE, expiry);
        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringQvlSignature.selector);
        _submitDefaultReceipt(vault, jobId, 1 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, valid, valid);

        vm.prank(tee);
        _submitDefaultReceipt(vault, jobId, 1 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, valid, validQvl);
        vm.prank(tee);
        vm.expectPartialRevert(ComputeCreditVault.InvalidJobState.selector);
        _submitDefaultReceipt(vault, jobId, 1 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, valid, validQvl);
    }

    function test_MeteringSignaturesBindReviewedUsageEvidenceDebitAndExpiry() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("bound-metering");
        _authorize(_authorization(jobId, address(0), 2 ether, NATIVE_POLICY));
        _start(jobId);
        uint256 expiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME() - 1;
        (bytes memory signature, bytes memory qvlSignature) =
            _signDefaultReceipts(vault, jobId, 1 ether, ATTESTATION_EVIDENCE, expiry);

        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        _submitDefaultReceipt(
            vault, jobId, 2 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, signature, qvlSignature
        );

        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.ZeroCommitment.selector);
        _submitDefaultReceipt(vault, jobId, 1 ether, COMPOSE_HASH, bytes32(0), expiry, signature, qvlSignature);

        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        _submitDefaultReceipt(
            vault, jobId, 1 ether, COMPOSE_HASH, keccak256("other-evidence"), expiry, signature, qvlSignature
        );

        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        _submitDefaultReceipt(
            vault, jobId, 1 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry + 1, signature, qvlSignature
        );

        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        vault.submitMeteringReceipt(
            jobId,
            1 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS + 1,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            expiry,
            signature,
            qvlSignature
        );
    }

    function test_MeterAndQvlRejectCrossWorkloadManifestAndDispatchIntentReplay() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("exact-execution-commitment-replay");
        _authorize(_authorization(jobId, address(0), 2 ether, NATIVE_POLICY));
        _start(jobId);
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        MeteredTerms memory terms = MeteredTerms({
            jobId: jobId,
            actualAssetDebit: 1 ether,
            billableComputeUnits: BILLABLE_COMPUTE_UNITS,
            usageStartedAt: job.startedAt,
            usageEndedAt: block.timestamp,
            attestationEvidenceHash: ATTESTATION_EVIDENCE,
            receiptExpiry: block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME()
        });

        _assertCommitmentVariantRejected(
            vault,
            terms,
            ExactExecutionCommitments({
                workload: keccak256("wrong-workload"), manifest: MANIFEST, dispatchIntent: DISPATCH_INTENT
            })
        );
        _assertCommitmentVariantRejected(
            vault,
            terms,
            ExactExecutionCommitments({
                workload: WORKLOAD, manifest: keccak256("wrong-manifest"), dispatchIntent: DISPATCH_INTENT
            })
        );
        _assertCommitmentVariantRejected(
            vault,
            terms,
            ExactExecutionCommitments({
                workload: WORKLOAD, manifest: MANIFEST, dispatchIntent: keccak256("wrong-dispatch-intent")
            })
        );

        assertEq(uint8(vault.getJob(jobId).state), uint8(ComputeCreditVault.JobState.Started));
    }

    function test_MeteringReceiptsCannotReplayAcrossJobChainOrContractDomains() public {
        ComputeCreditVault secondVault = new ComputeCreditVault(owner, developer, 500);
        ConfigurableCreditERC20 secondToken = new ConfigurableCreditERC20();
        _configure(secondVault, address(secondToken), owner, tee, provider, verifier);
        _fundNative(4 ether);
        bytes32 firstJobId = keccak256("receipt-domain-first");
        bytes32 secondJobId = keccak256("receipt-domain-second");
        _authorize(_authorization(firstJobId, address(0), 1 ether, NATIVE_POLICY));
        _authorize(_authorization(secondJobId, address(0), 1 ether, NATIVE_POLICY));
        _start(firstJobId);
        _start(secondJobId);
        uint256 receiptExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        (bytes memory firstMeterSignature, bytes memory firstQvlSignature) =
            _signDefaultReceipts(vault, firstJobId, 1 ether, ATTESTATION_EVIDENCE, receiptExpiry);

        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        vm.prank(tee);
        _submitDefaultReceipt(
            vault,
            secondJobId,
            1 ether,
            COMPOSE_HASH,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            firstMeterSignature,
            firstQvlSignature
        );

        uint256 originalChainId = block.chainid;
        vm.chainId(originalChainId + 1);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        vm.prank(tee);
        _submitDefaultReceipt(
            vault,
            firstJobId,
            1 ether,
            COMPOSE_HASH,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            firstMeterSignature,
            firstQvlSignature
        );
        vm.chainId(originalChainId);

        vm.prank(sponsor);
        secondVault.fundNative{value: 1 ether}(PROJECT, user);
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(firstJobId, address(0), 1 ether, NATIVE_POLICY);
        authorization.nonce = 0;
        secondVault.authorizeJob(authorization, _signAuthorization(secondVault, authorization));
        vm.prank(tee);
        secondVault.startJob(firstJobId, COMPOSE_HASH);
        ComputeCreditVault.Job memory secondJob = secondVault.getJob(firstJobId);
        vm.expectRevert(ComputeCreditVault.InvalidMeteringSignature.selector);
        vm.prank(tee);
        secondVault.submitMeteringReceipt(
            firstJobId,
            1 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            secondJob.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            firstMeterSignature,
            firstQvlSignature
        );
    }

    function test_MeteringRejectsInvalidUsageWindowAndOverlongReceiptLease() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("invalid-metered-usage");
        _authorize(_authorization(jobId, address(0), 1 ether, NATIVE_POLICY));
        _start(jobId);
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        uint256 validExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        (bytes memory meterSignature, bytes memory qvlSignature) =
            _signDefaultReceipts(vault, jobId, 1 ether, ATTESTATION_EVIDENCE, validExpiry);

        vm.expectRevert(ComputeCreditVault.InvalidMeteredUsage.selector);
        vm.prank(tee);
        vault.submitMeteringReceipt(
            jobId,
            1 ether,
            COMPOSE_HASH,
            0,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            validExpiry,
            meterSignature,
            qvlSignature
        );

        vm.expectRevert(ComputeCreditVault.InvalidMeteredUsage.selector);
        vm.prank(tee);
        vault.submitMeteringReceipt(
            jobId,
            1 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt + 1,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            validExpiry,
            meterSignature,
            qvlSignature
        );

        uint256 overlongExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME() + 1;
        vm.expectRevert(ComputeCreditVault.InvalidReceiptExpiry.selector);
        vm.prank(tee);
        vault.submitMeteringReceipt(
            jobId,
            1 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            overlongExpiry,
            meterSignature,
            qvlSignature
        );
    }

    function test_TimestampNarrowingRejectsValuesAboveUint64() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("timestamp-narrowing");
        _authorize(_authorization(jobId, address(0), 1 ether, NATIVE_POLICY));
        _start(jobId);
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        uint256 aboveUint64 = uint256(type(uint64).max) + 1;
        uint256 validExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();

        vm.expectRevert(ComputeCreditVault.InvalidMeteredUsage.selector);
        vm.prank(tee);
        vault.submitMeteringReceipt(
            jobId,
            1 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            aboveUint64,
            ATTESTATION_EVIDENCE,
            validExpiry,
            hex"00",
            hex"00"
        );

        vm.expectRevert(ComputeCreditVault.InvalidReceiptExpiry.selector);
        vm.prank(tee);
        vault.submitMeteringReceipt(
            jobId,
            1 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            aboveUint64,
            hex"00",
            hex"00"
        );

        vm.expectRevert(ComputeCreditVault.TimestampOverflow.selector);
        vault.startCommitmentFor(jobId, tee, COMPOSE_HASH, aboveUint64);
    }

    function test_MeteringRequiresLiveTeeAndComposeReleaseGates() public {
        _fundNative(5 ether);
        bytes32 jobId = keccak256("gates");
        _authorize(_authorization(jobId, address(0), 1 ether, NATIVE_POLICY));
        vm.expectRevert(ComputeCreditVault.TeeIdentityNotApproved.selector);
        vm.prank(stranger);
        vault.startJob(jobId, COMPOSE_HASH);

        _start(jobId);
        uint256 expiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        (bytes memory valid, bytes memory validQvl) =
            _signDefaultReceipts(vault, jobId, 1 ether, ATTESTATION_EVIDENCE, expiry);

        vm.prank(owner);
        vault.revokeComposeHash(COMPOSE_HASH);
        vm.expectRevert(ComputeCreditVault.ReleasePolicyNotReady.selector);
        vm.prank(tee);
        _submitDefaultReceipt(vault, jobId, 1 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, valid, validQvl);
    }

    function test_RiskIncreasingActionsRequireCompleteFrozenReleaseAndSignedNonzeroExecutionCommitments() public {
        ComputeCreditVault target = new ComputeCreditVault(owner, developer, 500);
        vm.expectRevert(ComputeCreditVault.ReleasePolicyNotReady.selector);
        vm.prank(owner);
        target.setPaused(false);

        ConfigurableCreditERC20 targetToken = new ConfigurableCreditERC20();
        _configure(target, address(targetToken), owner, tee, provider, verifier);
        vm.prank(sponsor);
        target.fundNative{value: 1 ether}(PROJECT, user);
        ComputeCreditVault.JobAuthorization memory authorization = ComputeCreditVault.JobAuthorization({
            projectId: PROJECT,
            jobId: keccak256("unfrozen-compose"),
            user: user,
            asset: address(0),
            nonce: 0,
            maxAssetDebit: 1 ether,
            expiry: block.timestamp + 1 days,
            ratePolicyCommitment: NATIVE_POLICY,
            workloadCommitment: WORKLOAD,
            manifestCommitment: MANIFEST,
            dispatchIntentCommitment: DISPATCH_INTENT
        });
        target.authorizeJob(authorization, _signAuthorization(target, authorization));

        authorization.workloadCommitment = bytes32(0);
        authorization.jobId = keccak256("zero-workload");
        authorization.nonce = 1;
        bytes memory zeroCommitmentSignature = _signAuthorization(target, authorization);
        vm.expectRevert(ComputeCreditVault.ZeroCommitment.selector);
        target.authorizeJob(authorization, zeroCommitmentSignature);
    }

    function test_StartPreventsUserFrontRunCancellationAndBindsExecutionIdentity() public {
        _fundNative(3 ether);
        bytes32 jobId = keccak256("non-cancelable-dispatch");
        _authorize(_authorization(jobId, address(0), 2 ether, NATIVE_POLICY));
        _start(jobId);

        ComputeCreditVault.Job memory started = vault.getJob(jobId);
        assertEq(uint8(started.state), uint8(ComputeCreditVault.JobState.Started));
        assertEq(started.teeIdentity, tee);
        assertEq(started.composeHash, COMPOSE_HASH);
        assertEq(started.startCommitment, vault.startCommitmentFor(jobId, tee, COMPOSE_HASH, started.startedAt));
        assertEq(started.workloadCommitment, WORKLOAD);
        assertEq(started.manifestCommitment, MANIFEST);
        assertEq(started.dispatchIntentCommitment, DISPATCH_INTENT);
        vm.expectPartialRevert(ComputeCreditVault.InvalidJobState.selector);
        vm.prank(user);
        vault.cancelJob(jobId);
        _assertCredit(address(0), 1 ether, 2 ether);

        address secondTee = makeAddr("second-tee");
        uint256 expiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        (bytes memory signature, bytes memory qvlSignature) =
            _signDefaultReceipts(vault, jobId, 1 ether, ATTESTATION_EVIDENCE, expiry);
        vm.expectRevert(ComputeCreditVault.ComposeIdentityMismatch.selector);
        vm.prank(secondTee);
        _submitDefaultReceipt(
            vault, jobId, 1 ether, COMPOSE_HASH, ATTESTATION_EVIDENCE, expiry, signature, qvlSignature
        );

        bytes32 otherCompose = keccak256("other-compose");
        vm.expectRevert(ComputeCreditVault.ComposeIdentityMismatch.selector);
        vm.prank(tee);
        _submitDefaultReceipt(
            vault, jobId, 1 ether, otherCompose, ATTESTATION_EVIDENCE, expiry, signature, qvlSignature
        );
    }

    function test_PermissionlessExpiryReleasesStartedReservation() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("started-expiry");
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(jobId, address(0), 2 ether, NATIVE_POLICY);
        authorization.expiry = block.timestamp + 2 hours;
        _authorize(authorization);
        _start(jobId);
        vm.warp(authorization.expiry + 1);
        vm.prank(stranger);
        vault.expireJob(jobId);
        _assertCredit(address(0), 2 ether, 0);
        assertEq(uint8(vault.getJob(jobId).state), uint8(ComputeCreditVault.JobState.Expired));
    }

    function test_RevokedRateOrAssetStopsNewAuthorizationAndSettlement() public {
        _fundToken(10 ether);
        bytes32 jobId = keccak256("revocation");
        _authorize(_authorization(jobId, address(token), 5 ether, TOKEN_POLICY));
        _start(jobId);
        uint256 jobStartedAt = vault.getJob(jobId).startedAt;
        uint256 receiptExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();

        vm.prank(owner);
        vault.revokeRatePolicy(TOKEN_POLICY);
        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.ReleasePolicyNotReady.selector);
        vault.submitMeteringReceipt(
            jobId,
            1 ether,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            jobStartedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            hex"00",
            hex"00"
        );

        vm.prank(owner);
        vault.revokeAsset(address(token));
        ComputeCreditVault.JobAuthorization memory next =
            _authorization(keccak256("revoked-new"), address(token), 1, TOKEN_POLICY);
        bytes memory nextSignature = _signAuthorization(vault, next);
        vm.expectRevert(ComputeCreditVault.ReleasePolicyNotReady.selector);
        vault.authorizeJob(next, nextSignature);
    }

    function test_ReceiptAndAuthorizationExpiryAreEnforced() public {
        _fundNative(2 ether);
        bytes32 jobId = keccak256("expiry-gates");
        ComputeCreditVault.JobAuthorization memory authorization =
            _authorization(jobId, address(0), 1 ether, NATIVE_POLICY);
        authorization.expiry = block.timestamp + 2 hours;
        _authorize(authorization);
        _start(jobId);
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        uint256 overlongReceiptExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME() + 1;

        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidReceiptExpiry.selector);
        vault.submitMeteringReceipt(
            jobId,
            1,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            block.timestamp - 1,
            hex"00",
            hex"00"
        );

        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidReceiptExpiry.selector);
        vault.submitMeteringReceipt(
            jobId,
            1,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            overlongReceiptExpiry,
            hex"00",
            hex"00"
        );

        vm.warp(authorization.expiry + 1);
        vm.prank(tee);
        vm.expectRevert(ComputeCreditVault.InvalidAuthorizationExpiry.selector);
        vault.submitMeteringReceipt(
            jobId,
            1,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            authorization.expiry,
            ATTESTATION_EVIDENCE,
            authorization.expiry,
            hex"00",
            hex"00"
        );
    }

    function test_WithdrawalsArePullBasedExactAndConserveBothAssets() public {
        _fundNative(3 ether);
        _fundToken(400 ether);
        uint256 userNativeBefore = user.balance;
        uint256 userTokenBefore = token.balanceOf(user);

        vm.startPrank(user);
        vault.withdrawUnused(PROJECT, address(0), 1 ether);
        vault.withdrawUnused(PROJECT, address(token), 100 ether);
        vm.stopPrank();
        assertEq(user.balance - userNativeBefore, 1 ether);
        assertEq(token.balanceOf(user) - userTokenBefore, 100 ether);
        assertEq(vault.totalLiability(address(0)), 2 ether);
        assertEq(vault.totalLiability(address(token)), 300 ether);

        bytes32 jobId = keccak256("provider-withdraw");
        _authorize(_authorization(jobId, address(0), 2 ether, NATIVE_POLICY));
        _settle(jobId, 2 ether);
        uint256 providerBefore = provider.balance;
        vm.prank(provider);
        vault.withdrawAccrued(address(0));
        assertEq(provider.balance - providerBefore, 1.9 ether);
        uint256 developerBefore = developer.balance;
        vm.prank(developer);
        vault.withdrawAccrued(address(0));
        assertEq(developer.balance - developerBefore, 0.1 ether);
        assertEq(vault.totalLiability(address(0)), 0);
        assertEq(address(vault).balance, 0);
    }

    function test_PauseStopsRiskIncreasingActionsButNotReleaseOrWithdrawal() public {
        _fundNative(4 ether);
        bytes32 cancelId = keccak256("pause-cancel");
        _authorize(_authorization(cancelId, address(0), 1 ether, NATIVE_POLICY));
        bytes32 settleId = keccak256("pause-settle");
        _authorize(_authorization(settleId, address(0), 1 ether, NATIVE_POLICY));

        vm.prank(owner);
        vault.setPaused(true);
        vm.prank(sponsor);
        vm.expectRevert(ComputeCreditVault.Paused.selector);
        vault.fundNative{value: 1}(PROJECT, user);

        ComputeCreditVault.JobAuthorization memory blocked =
            _authorization(keccak256("pause-auth"), address(0), 1, NATIVE_POLICY);
        bytes memory blockedSignature = _signAuthorization(vault, blocked);
        vm.expectRevert(ComputeCreditVault.Paused.selector);
        vault.authorizeJob(blocked, blockedSignature);

        vm.expectRevert(ComputeCreditVault.Paused.selector);
        vm.prank(tee);
        vault.startJob(settleId, COMPOSE_HASH);

        uint256 pausedReceiptExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        vm.expectRevert(ComputeCreditVault.Paused.selector);
        vm.prank(tee);
        vault.submitMeteringReceipt(
            settleId,
            1,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            block.timestamp,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            pausedReceiptExpiry,
            hex"00",
            hex"00"
        );

        vm.prank(user);
        vault.cancelJob(cancelId);
        vm.prank(user);
        vault.withdrawUnused(PROJECT, address(0), 1 ether);
        assertEq(user.balance, 11 ether);
    }

    function test_OutgoingFeeTokenRevertsAndRestoresAccounting() public {
        _fundToken(100 ether);
        token.setBehavior(100, false, false);
        vm.prank(user);
        vm.expectRevert(ComputeCreditVault.AssetAmountMismatch.selector);
        vault.withdrawUnused(PROJECT, address(token), 100 ether);

        _assertCredit(address(token), 100 ether, 0);
        assertEq(vault.totalLiability(address(token)), 100 ether);
        assertEq(token.balanceOf(address(vault)), 100 ether);
        assertEq(token.balanceOf(user), 0);
    }

    function test_RevertingNativeReceiverCannotCorruptAccounting() public {
        RevertingCreditReceiver receiver = new RevertingCreditReceiver(vault);
        vm.prank(sponsor);
        vault.fundNative{value: 2 ether}(PROJECT, address(receiver));

        vm.expectRevert(ComputeCreditVault.TransferFailed.selector);
        receiver.withdraw(PROJECT, 1 ether);
        (uint256 available, uint256 reserved) = vault.credits(PROJECT, address(receiver), address(0));
        assertEq(available, 2 ether);
        assertEq(reserved, 0);
        assertEq(vault.totalLiability(address(0)), 2 ether);
    }

    function test_ReentrantNativeReceiverCannotDoubleWithdraw() public {
        ReentrantCreditReceiver receiver = new ReentrantCreditReceiver(vault);
        vm.prank(sponsor);
        vault.fundNative{value: 2 ether}(PROJECT, address(receiver));
        receiver.withdraw(PROJECT, 1 ether);

        assertEq(receiver.received(), 1 ether);
        assertFalse(receiver.reentrySucceeded());
        (uint256 available, uint256 reserved) = vault.credits(PROJECT, address(receiver), address(0));
        assertEq(available, 1 ether);
        assertEq(reserved, 0);
        assertEq(vault.totalLiability(address(0)), 1 ether);
    }

    function test_RoundingAlwaysFavorsProviderAndConservesDebit() public {
        _fundNative(101);
        bytes32 jobId = keccak256("rounding");
        _authorize(_authorization(jobId, address(0), 101, NATIVE_POLICY));
        _settle(jobId, 101);
        assertEq(vault.claimableAccrual(address(0), developer), 5);
        assertEq(vault.claimableAccrual(address(0), provider), 96);
        assertEq(vault.claimableAccrual(address(0), developer) + vault.claimableAccrual(address(0), provider), 101);
    }

    function testFuzz_NativeSettlementConservesEveryUnit(uint96 fundingRaw, uint96 capRaw, uint96 debitRaw) public {
        uint256 funding = bound(uint256(fundingRaw), 1, 100 ether);
        uint256 cap = bound(uint256(capRaw), 1, funding);
        uint256 debit = bound(uint256(debitRaw), 0, cap);
        _fundNative(funding);
        bytes32 jobId = keccak256(abi.encode("native-fuzz", funding, cap, debit));
        _authorize(_authorization(jobId, address(0), cap, NATIVE_POLICY));
        _settle(jobId, debit);

        (uint256 available, uint256 reserved) = vault.credits(PROJECT, user, address(0));
        uint256 providerClaim = vault.claimableAccrual(address(0), provider);
        uint256 developerClaim = vault.claimableAccrual(address(0), developer);
        assertEq(reserved, 0);
        assertEq(available, funding - debit);
        assertEq(providerClaim + developerClaim, debit);
        assertEq(available + providerClaim + developerClaim, vault.totalLiability(address(0)));
        assertEq(vault.totalLiability(address(0)), address(vault).balance);
    }

    function testFuzz_TokenSettlementConservesEveryUnit(uint96 fundingRaw, uint96 capRaw, uint96 debitRaw) public {
        uint256 funding = bound(uint256(fundingRaw), 1, 1_000_000 ether);
        uint256 cap = bound(uint256(capRaw), 1, funding);
        uint256 debit = bound(uint256(debitRaw), 0, cap);
        _fundToken(funding);
        bytes32 jobId = keccak256(abi.encode("token-fuzz", funding, cap, debit));
        _authorize(_authorization(jobId, address(token), cap, TOKEN_POLICY));
        _settle(jobId, debit);

        (uint256 available, uint256 reserved) = vault.credits(PROJECT, user, address(token));
        uint256 providerClaim = vault.claimableAccrual(address(token), provider);
        uint256 developerClaim = vault.claimableAccrual(address(token), developer);
        assertEq(reserved, 0);
        assertEq(available, funding - debit);
        assertEq(providerClaim + developerClaim, debit);
        assertEq(available + providerClaim + developerClaim, vault.totalLiability(address(token)));
        assertEq(vault.totalLiability(address(token)), token.balanceOf(address(vault)));
    }
}

contract ComputeCreditVaultHandler is Test {
    ComputeCreditVault public immutable vault;
    ConfigurableCreditERC20 public immutable token;
    address public immutable user;
    address public immutable provider;
    address public immutable developer;
    address public immutable tee;
    uint256 internal immutable userKey;
    uint256 internal immutable verifierKey;
    uint256 internal immutable qvlKey;

    bytes32 internal constant PROJECT = keccak256("invariant-project");
    bytes32 internal constant NATIVE_POLICY = keccak256("native-rate-v1");
    bytes32 internal constant TOKEN_POLICY = keccak256("token-rate-v1");
    bytes32 internal constant COMPOSE_HASH = keccak256("reproducible-compose-digest");
    bytes32 internal constant ATTESTATION_EVIDENCE = keccak256("invariant-attestation-evidence");
    uint256 internal constant BILLABLE_COMPUTE_UNITS = 42;
    uint256 internal nextJob;
    bytes32[] internal jobs;

    constructor(
        ComputeCreditVault target,
        ConfigurableCreditERC20 configuredToken,
        uint256 configuredUserKey,
        uint256 configuredVerifierKey,
        uint256 configuredQvlKey,
        address configuredProvider,
        address configuredDeveloper,
        address configuredTee
    ) {
        vault = target;
        token = configuredToken;
        userKey = configuredUserKey;
        verifierKey = configuredVerifierKey;
        qvlKey = configuredQvlKey;
        user = vm.addr(configuredUserKey);
        provider = configuredProvider;
        developer = configuredDeveloper;
        tee = configuredTee;
        configuredToken.approve(address(target), type(uint256).max);
    }

    function fundNative(uint96 rawAmount) external {
        uint256 amount = bound(uint256(rawAmount), 1, 10 ether);
        if (address(this).balance < amount) return;
        vault.fundNative{value: amount}(PROJECT, user);
    }

    function fundToken(uint96 rawAmount) external {
        uint256 amount = bound(uint256(rawAmount), 1, 10_000 ether);
        token.mint(address(this), amount);
        vault.fundERC20(PROJECT, user, address(token), amount);
    }

    function authorizeNative(uint96 rawCap) external {
        _authorize(address(0), NATIVE_POLICY, rawCap);
    }

    function authorizeToken(uint96 rawCap) external {
        _authorize(address(token), TOKEN_POLICY, rawCap);
    }

    function settle(uint256 seed, uint96 rawDebit) external {
        if (jobs.length == 0) return;
        bytes32 jobId = jobs[seed % jobs.length];
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        if (block.timestamp > job.authorizationExpiry) return;
        if (job.state == ComputeCreditVault.JobState.Authorized) {
            vm.prank(tee);
            vault.startJob(jobId, COMPOSE_HASH);
            job = vault.getJob(jobId);
        }
        if (job.state != ComputeCreditVault.JobState.Started) return;
        uint256 debit = bound(uint256(rawDebit), 0, job.maxAssetDebit);
        uint256 receiptExpiry = block.timestamp + vault.MAX_METERING_RECEIPT_LIFETIME();
        if (receiptExpiry > job.authorizationExpiry) receiptExpiry = job.authorizationExpiry;
        bytes32 digest = vault.meteringReceiptDigest(
            jobId, debit, BILLABLE_COMPUTE_UNITS, job.startedAt, block.timestamp, ATTESTATION_EVIDENCE, receiptExpiry
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierKey, digest);
        bytes32 qvlDigest = vault.meteringQvlReceiptDigest(
            jobId, debit, BILLABLE_COMPUTE_UNITS, job.startedAt, block.timestamp, ATTESTATION_EVIDENCE, receiptExpiry
        );
        (uint8 qvlV, bytes32 qvlR, bytes32 qvlS) = vm.sign(qvlKey, qvlDigest);
        vm.prank(tee);
        vault.submitMeteringReceipt(
            jobId,
            debit,
            COMPOSE_HASH,
            BILLABLE_COMPUTE_UNITS,
            job.startedAt,
            block.timestamp,
            ATTESTATION_EVIDENCE,
            receiptExpiry,
            abi.encodePacked(r, s, v),
            abi.encodePacked(qvlR, qvlS, qvlV)
        );
    }

    function start(uint256 seed) external {
        if (jobs.length == 0) return;
        bytes32 jobId = jobs[seed % jobs.length];
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        if (job.state != ComputeCreditVault.JobState.Authorized || block.timestamp > job.authorizationExpiry) return;
        vm.prank(tee);
        vault.startJob(jobId, COMPOSE_HASH);
    }

    function cancel(uint256 seed) external {
        if (jobs.length == 0) return;
        bytes32 jobId = jobs[seed % jobs.length];
        ComputeCreditVault.Job memory job = vault.getJob(jobId);
        if (job.state != ComputeCreditVault.JobState.Authorized) return;
        vm.prank(user);
        vault.cancelJob(jobId);
    }

    function withdrawUnusedNative(uint96 rawAmount) external {
        _withdrawUnused(address(0), rawAmount);
    }

    function withdrawUnusedToken(uint96 rawAmount) external {
        _withdrawUnused(address(token), rawAmount);
    }

    function withdrawProviderNative() external {
        _withdrawAccrued(address(0), provider);
    }

    function withdrawProviderToken() external {
        _withdrawAccrued(address(token), provider);
    }

    function withdrawDeveloperNative() external {
        _withdrawAccrued(address(0), developer);
    }

    function withdrawDeveloperToken() external {
        _withdrawAccrued(address(token), developer);
    }

    function _authorize(address asset, bytes32 policy, uint96 rawCap) internal {
        (uint256 available,) = vault.credits(PROJECT, user, asset);
        if (available == 0) return;
        uint256 cap = bound(uint256(rawCap), 1, available);
        bytes32 jobId = keccak256(abi.encode("invariant-job", ++nextJob));
        ComputeCreditVault.JobAuthorization memory authorization = ComputeCreditVault.JobAuthorization({
            projectId: PROJECT,
            jobId: jobId,
            user: user,
            asset: asset,
            nonce: vault.nextAuthorizationNonce(PROJECT, user),
            maxAssetDebit: cap,
            expiry: block.timestamp + 2 days,
            ratePolicyCommitment: policy,
            workloadCommitment: keccak256("invariant-workload"),
            manifestCommitment: keccak256("invariant-manifest"),
            dispatchIntentCommitment: keccak256(abi.encode("invariant-dispatch", jobId))
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, vault.jobAuthorizationDigest(authorization));
        vault.authorizeJob(authorization, abi.encodePacked(r, s, v));
        jobs.push(jobId);
    }

    function _withdrawUnused(address asset, uint96 rawAmount) internal {
        (uint256 available,) = vault.credits(PROJECT, user, asset);
        if (available == 0) return;
        uint256 amount = bound(uint256(rawAmount), 1, available);
        vm.prank(user);
        vault.withdrawUnused(PROJECT, asset, amount);
    }

    function _withdrawAccrued(address asset, address recipient) internal {
        if (vault.claimableAccrual(asset, recipient) == 0) return;
        vm.prank(recipient);
        vault.withdrawAccrued(asset);
    }

    receive() external payable {}
}

contract ComputeCreditVaultInvariantTest is StdInvariant, ComputeCreditVaultFixture {
    ComputeCreditVaultHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new ComputeCreditVaultHandler(vault, token, USER_KEY, VERIFIER_KEY, QVL_KEY, provider, developer, tee);
        vm.deal(address(handler), 1_000_000 ether);
        targetContract(address(handler));
    }

    function invariant_NativeLiabilityIsExactlyBackedAndFullyAllocated() public view {
        (uint256 available, uint256 reserved) = vault.credits(keccak256("invariant-project"), user, address(0));
        uint256 allocated = available + reserved + vault.claimableAccrual(address(0), provider)
            + vault.claimableAccrual(address(0), developer);
        assertEq(allocated, vault.totalLiability(address(0)));
        assertEq(vault.totalLiability(address(0)), address(vault).balance);
        assertEq(vault.surplus(address(0)), 0);
    }

    function invariant_TokenLiabilityIsExactlyBackedAndFullyAllocated() public view {
        (uint256 available, uint256 reserved) = vault.credits(keccak256("invariant-project"), user, address(token));
        uint256 allocated = available + reserved + vault.claimableAccrual(address(token), provider)
            + vault.claimableAccrual(address(token), developer);
        assertEq(allocated, vault.totalLiability(address(token)));
        assertEq(vault.totalLiability(address(token)), token.balanceOf(address(vault)));
        assertEq(vault.surplus(address(token)), 0);
    }
}
