// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {DeployFreshSuiteScript} from "../script/DeployFreshSuite.s.sol";
import {EmailOracleAuthScript} from "../script/EmailOracleAuth.s.sol";
import {ChallengeRegistry} from "../src/ChallengeRegistry.sol";
import {ComputeCreditVault} from "../src/ComputeCreditVault.sol";
import {DiligenceRoom} from "../src/DiligenceRoom.sol";
import {EmailOracleAuth} from "../src/EmailOracleAuth.sol";
import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";
import {RoyaltyDistributor} from "../src/RoyaltyDistributor.sol";
import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

contract DeployFreshSuiteHarness is DeployFreshSuiteScript {
    function reviewedComputeDeveloperFee(uint256 feeBps) external pure returns (uint16) {
        return _reviewedComputeDeveloperFee(feeBps);
    }
}

contract DeployFreshSuiteTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 internal constant POLICY_UNIT = 1e18;

    DeployFreshSuiteScript internal script;
    address internal operator;
    address internal diligenceGovernanceController = makeAddr("diligence-governance-controller");
    address internal computeDeveloper = makeAddr("compute-developer");
    bytes32 internal accountCommitment = keccak256("tinker-account-commitment");
    bytes32 internal composeHash = keccak256("tinker-compose-hash");
    bytes32 internal deploymentIntentSha256 = keccak256("deployment-intent-sha256");
    bytes32 internal reviewerAuthorityGenesisAcceptanceSha256 =
        keccak256("reviewer-authority-genesis-acceptance-sha256");

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        vm.setEnv("DEPLOYMENT_OPERATOR", vm.toString(operator));
        vm.setEnv("DILIGENCE_GOVERNANCE_CONTROLLER", vm.toString(diligenceGovernanceController));
        vm.setEnv("COMPUTE_VAULT_DEVELOPER", vm.toString(computeDeveloper));
        vm.setEnv("COMPUTE_VAULT_DEVELOPER_FEE_BPS", "100");
        vm.setEnv("TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT", vm.toString(accountCommitment));
        vm.setEnv("TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI", "5000000000000000000");
        vm.setEnv("TINKER_ENCUMBRANCE_MAX_SPEND_WEI", "2000000000000000000");
        vm.setEnv("EMAIL_ORACLE_UPGRADE_DELAY", "172800");
        vm.setEnv("DEPLOYMENT_INTENT_SHA256_BYTES32", vm.toString(deploymentIntentSha256));
        vm.setEnv(
            "REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32",
            vm.toString(reviewerAuthorityGenesisAcceptanceSha256)
        );
        script = new DeployFreshSuiteScript();
    }

    function test_DeploysFreshEmailOracleDenyAllUnderSameOperator() public {
        (
            DiligenceRoom room,
            TinkerAccountEncumbrance encumbrance,
            RoyaltyDistributor royalties,
            ChallengeRegistry challenges,
            ComputeCreditVault computeVault,
            EmailOracleAuth emailOracleAuth,
            ExecutionPolicyAnchor executionPolicyAnchor
        ) = script.run();

        assertGt(address(room).code.length, 0);
        assertGt(address(encumbrance).code.length, 0);
        assertGt(address(royalties).code.length, 0);
        assertGt(address(challenges).code.length, 0);
        assertGt(address(computeVault).code.length, 0);
        assertGt(address(emailOracleAuth).code.length, 0);
        assertGt(address(executionPolicyAnchor).code.length, 0);

        assertEq(room.developer(), operator);
        assertEq(room.initialDeveloper(), operator);
        assertEq(room.releaseGovernanceController(), diligenceGovernanceController);
        assertEq(room.pendingDeveloper(), address(0));
        assertEq(room.pendingDeveloperActivatesAt(), 0);
        assertEq(room.DEVELOPER_TRANSFER_DELAY(), 2 days);
        assertTrue(room.productionRelease());
        assertEq(room.dealCount(), 0);
        assertEq(room.resultVerifier(), address(0));
        assertEq(room.pendingResultVerifier(), address(0));
        assertEq(room.pendingResultVerifierActivatesAt(), 0);
        assertFalse(room.resultVerifierFrozen());
        assertEq(room.feeBps(), 100);
        assertTrue(room.feeBpsFrozen());
        assertEq(room.COMPUTE_SETTLEMENT_BPS(), 100);
        assertTrue(room.computeSettlementPolicyEnabled());
        assertTrue(room.composeApprovalRequired());
        assertTrue(room.teeIdentityApprovalRequired());
        assertTrue(room.approvalRequirementsFrozen());
        assertEq(room.attestationVerifier(), address(0));
        assertEq(room.attestationReleasePolicyHash(), bytes32(0));
        assertEq(room.pendingAttestationVerifier(), address(0));
        assertEq(room.pendingAttestationReleasePolicyHash(), bytes32(0));
        assertEq(room.pendingAttestationBindingActivatesAt(), 0);
        assertFalse(room.attestationBindingFrozen());
        bytes32[3] memory evaluatorPolicies = room.evaluatorPolicies();
        assertEq(evaluatorPolicies[0], bytes32(0));
        assertEq(evaluatorPolicies[1], bytes32(0));
        assertEq(evaluatorPolicies[2], bytes32(0));
        assertEq(room.approvedEvaluatorPolicyCount(), 0);
        assertEq(room.pendingEvaluatorPolicyCount(), 0);
        assertEq(room.evaluatorPolicySetRoot(), bytes32(0));
        assertFalse(room.evaluatorPolicySetFrozen());
        assertFalse(room.approvedComposeHashes(bytes32(0)));
        assertEq(room.teeIdentityComposeHash(address(0)), bytes32(0));
        assertEq(room.approvedComposeCount(), 0);
        assertEq(room.pendingComposeCount(), 0);
        assertEq(room.approvedTeeIdentityCount(), 0);
        assertEq(room.pendingTeeIdentityCount(), 0);
        assertFalse(room.composeAdditionsFrozen());
        assertFalse(room.teeIdentityAdditionsFrozen());
        assertEq(encumbrance.owner(), operator);
        assertEq(encumbrance.pendingOwner(), address(0));
        assertEq(encumbrance.accountCommitment(), accountCommitment);
        assertEq(encumbrance.maxAddBalanceWei(), 5 * POLICY_UNIT);
        assertEq(encumbrance.maxSpendWei(), 2 * POLICY_UNIT);
        assertTrue(encumbrance.emergencyHalted());
        assertFalse(encumbrance.releasePolicyFrozen());
        assertEq(encumbrance.releasePolicyCommitment(), bytes32(0));
        assertEq(encumbrance.releaseComposeCount(), 0);
        assertEq(encumbrance.releaseManagerCount(), 0);
        assertEq(encumbrance.approvedComposeCount(), 0);
        assertFalse(encumbrance.approvedComposeHashes(composeHash));
        assertEq(encumbrance.approvedComposeRoot(), encumbrance.computeComposeRoot(new bytes32[](0)));
        assertEq(encumbrance.managerCount(), 0);
        assertEq(encumbrance.managerRoot(), encumbrance.computeManagerRoot(new address[](0)));
        assertEq(encumbrance.pendingReleasePolicyCommitment(), bytes32(0));
        assertEq(encumbrance.pendingReleasePolicyActivatesAt(), 0);
        assertEq(encumbrance.pendingComposeCount(), 0);
        assertEq(encumbrance.pendingManagerCount(), 0);
        assertEq(royalties.owner(), operator);
        assertEq(royalties.pendingOwner(), address(0));
        assertTrue(royalties.paused());
        assertEq(royalties.settlementVerifier(), address(0));
        assertEq(royalties.qvlVerifier(), address(0));
        assertEq(royalties.executionPolicyAnchor(), address(0));
        assertEq(royalties.anchorWriterReleaseCommitment(), bytes32(0));
        assertEq(royalties.releasePolicyCommitment(), bytes32(0));
        assertEq(royalties.authorityNonce(), 0);
        assertEq(royalties.pendingAuthorityActivatesAt(), 0);
        assertFalse(royalties.pendingAuthorityRevocation());
        assertEq(challenges.owner(), operator);

        assertEq(computeVault.owner(), operator);
        assertEq(computeVault.developer(), computeDeveloper);
        assertEq(computeVault.meteringVerifier(), address(0));
        assertEq(computeVault.meteringQvlVerifier(), address(0));
        assertEq(computeVault.meteringPolicySetHash(), bytes32(0));
        assertEq(computeVault.pendingMeteringVerifier(), address(0));
        assertEq(computeVault.pendingMeteringQvlVerifier(), address(0));
        assertEq(computeVault.pendingMeteringPolicySetHash(), bytes32(0));
        assertEq(computeVault.pendingMeteringBindingActivatesAt(), 0);
        assertFalse(computeVault.meteringBindingFrozen());
        assertTrue(computeVault.paused());
        assertEq(computeVault.developerFeeBps(), 100);
        assertTrue(computeVault.developerFeeFrozen());
        assertEq(computeVault.approvedComposeCount(), 0);
        assertEq(computeVault.approvedTeeIdentityCount(), 0);
        assertEq(computeVault.allowedAssetCount(), 0);
        assertEq(computeVault.activeRatePolicyCount(), 0);
        assertEq(computeVault.pendingAssetCount(), 0);
        assertEq(computeVault.pendingRatePolicyCount(), 0);
        assertEq(computeVault.pendingComposeCount(), 0);
        assertEq(computeVault.pendingTeeIdentityCount(), 0);
        assertFalse(computeVault.composePolicyFrozen());
        assertFalse(computeVault.teeIdentityAdditionsFrozen());
        assertFalse(computeVault.ratePolicyAdditionsFrozen());
        assertFalse(computeVault.assetAdditionsFrozen());

        assertEq(emailOracleAuth.owner(), operator);
        assertTrue(emailOracleAuth.productionRelease());
        assertEq(emailOracleAuth.ORACLE_UPGRADE_DELAY(), 2 days);
        assertFalse(emailOracleAuth.allowAnyDevice());
        assertFalse(emailOracleAuth.oracleCodeFrozen());
        assertFalse(emailOracleAuth.consumerRegistryFrozen());
        assertFalse(emailOracleAuth.allowedOracleComposeHashes(bytes32(0)));
        assertFalse(emailOracleAuth.allowedDeviceIds(bytes32(0)));

        assertEq(executionPolicyAnchor.owner(), operator);
        assertEq(executionPolicyAnchor.deploymentIntentSha256(), deploymentIntentSha256);
        assertEq(
            executionPolicyAnchor.reviewerAuthorityGenesisAcceptanceSha256(), reviewerAuthorityGenesisAcceptanceSha256
        );
        assertEq(executionPolicyAnchor.writer(), address(0));
        assertEq(executionPolicyAnchor.writerReleaseCommitment(), bytes32(0));
        assertEq(executionPolicyAnchor.pendingWriter(), address(0));
        assertEq(executionPolicyAnchor.pendingWriterReleaseCommitment(), bytes32(0));
        assertEq(executionPolicyAnchor.pendingWriterActivatesAt(), 0);
        assertTrue(executionPolicyAnchor.paused());
        assertFalse(executionPolicyAnchor.writerRotationsFrozen());
        assertEq(executionPolicyAnchor.globalSequence(), 0);
        assertEq(executionPolicyAnchor.globalHead(), bytes32(0));
    }

    function test_StandaloneEmailOracleScriptRejectsBaseSepolia() public {
        EmailOracleAuthScript standalone = new EmailOracleAuthScript();

        vm.expectRevert(bytes("use DeployFreshSuite for Base EmailOracleAuth releases"));
        standalone.run();
    }

    function test_RejectsDeveloperFeeAboveFreshReleaseCap() public {
        DeployFreshSuiteHarness harness = new DeployFreshSuiteHarness();

        vm.expectRevert(bytes("compute developer fee exceeds fresh-release cap"));
        harness.reviewedComputeDeveloperFee(101);
    }

    function test_AcceptsDeveloperFeeAtFreshReleaseCap() public {
        DeployFreshSuiteHarness harness = new DeployFreshSuiteHarness();

        assertEq(harness.reviewedComputeDeveloperFee(100), 100);
    }
}
