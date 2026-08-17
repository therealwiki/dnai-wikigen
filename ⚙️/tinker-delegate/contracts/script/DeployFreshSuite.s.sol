// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {ChallengeRegistry} from "../src/ChallengeRegistry.sol";
import {ComputeCreditVault} from "../src/ComputeCreditVault.sol";
import {DiligenceRoom} from "../src/DiligenceRoom.sol";
import {EmailOracleAuth} from "../src/EmailOracleAuth.sol";
import {ExecutionPolicyAnchor} from "../src/ExecutionPolicyAnchor.sol";
import {RoyaltyDistributor} from "../src/RoyaltyDistributor.sol";
import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

/// @notice Deploy the reviewed-scope, fresh Base Sepolia contract suite.
/// @dev ComputeCreditVault and ExecutionPolicyAnchor both deploy fail-closed.
///      The vault has no active policy or TEE identity; the anchor is paused
///      with no writer. The suite still excludes challenge-prize and
///      candidate-custody contracts.
contract DeployFreshSuiteScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 internal constant MIN_EMAIL_ORACLE_UPGRADE_DELAY = 2 days;
    uint256 internal constant MAX_EMAIL_ORACLE_UPGRADE_DELAY = 365 days;
    uint256 internal constant MAX_FRESH_RELEASE_DEVELOPER_FEE_BPS = 100;

    function run()
        public
        returns (
            DiligenceRoom room,
            TinkerAccountEncumbrance encumbrance,
            RoyaltyDistributor royalties,
            ChallengeRegistry challenges,
            ComputeCreditVault computeVault,
            EmailOracleAuth emailOracleAuth,
            ExecutionPolicyAnchor executionPolicyAnchor
        )
    {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "fresh suite is Base Sepolia only");

        address operator = vm.envAddress("DEPLOYMENT_OPERATOR");
        address diligenceGovernanceController = vm.envAddress("DILIGENCE_GOVERNANCE_CONTROLLER");
        address computeDeveloper = vm.envAddress("COMPUTE_VAULT_DEVELOPER");
        uint256 computeDeveloperFeeBps = vm.envUint("COMPUTE_VAULT_DEVELOPER_FEE_BPS");
        bytes32 accountCommitment = vm.envBytes32("TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT");
        uint256 maxAddBalanceWei = vm.envUint("TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI");
        uint256 maxSpendWei = vm.envUint("TINKER_ENCUMBRANCE_MAX_SPEND_WEI");
        uint256 emailOracleUpgradeDelay = vm.envUint("EMAIL_ORACLE_UPGRADE_DELAY");
        bytes32 deploymentIntentSha256 = vm.envBytes32("DEPLOYMENT_INTENT_SHA256_BYTES32");
        bytes32 reviewerAuthorityGenesisAcceptanceSha256 =
            vm.envBytes32("REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32");

        require(operator != address(0), "DEPLOYMENT_OPERATOR must be nonzero");
        require(
            diligenceGovernanceController != address(0) && diligenceGovernanceController != operator,
            "DILIGENCE_GOVERNANCE_CONTROLLER must be nonzero and separate from operator"
        );
        require(
            diligenceGovernanceController != computeDeveloper,
            "diligence governance controller must be separate from compute developer"
        );
        require(computeDeveloper != address(0), "COMPUTE_VAULT_DEVELOPER must be nonzero");
        require(computeDeveloper != operator, "compute developer must be separate from operator");
        uint16 reviewedComputeDeveloperFeeBps = _reviewedComputeDeveloperFee(computeDeveloperFeeBps);
        require(accountCommitment != bytes32(0), "account commitment must be nonzero");
        require(deploymentIntentSha256 != bytes32(0), "deployment intent digest must be nonzero");
        require(
            reviewerAuthorityGenesisAcceptanceSha256 != bytes32(0),
            "reviewer authority genesis acceptance digest must be nonzero"
        );
        require(
            emailOracleUpgradeDelay >= MIN_EMAIL_ORACLE_UPGRADE_DELAY,
            "email oracle upgrade delay must be at least 2 days"
        );
        require(
            emailOracleUpgradeDelay <= MAX_EMAIL_ORACLE_UPGRADE_DELAY,
            "email oracle upgrade delay must be at most 365 days"
        );

        vm.startBroadcast();

        // Production posture is constructor-bound so the room is fail-closed
        // in the deployment transaction, before the later governance calls.
        room = new DiligenceRoom(true, diligenceGovernanceController);
        require(room.developer() == operator, "broadcast signer does not match DEPLOYMENT_OPERATOR");
        require(room.initialDeveloper() == operator, "diligence initial developer mismatch");
        require(
            room.releaseGovernanceController() == diligenceGovernanceController,
            "diligence release governance controller mismatch"
        );
        require(
            room.pendingDeveloper() == address(0) && room.pendingDeveloperActivatesAt() == 0,
            "diligence governance handoff must start unstaged"
        );
        require(room.productionRelease(), "diligence room must deploy in production mode");
        // The public settlement meter must be deterministic for every deal in
        // this release. Freeze the reviewed 1% default before any contract can
        // be exposed to users.
        require(room.feeBps() == room.DEFAULT_FEE_BPS(), "unexpected diligence fee");
        room.freezeFeeBps();
        require(room.COMPUTE_SETTLEMENT_BPS() == 100, "unexpected compute settlement tariff");
        room.enableComputeSettlementPolicy();
        // Permanently require both approval layers before any CVM is admitted.
        // The fresh mappings are empty, so the room starts fail-closed while
        // the exact compose and TEE binding await staged timelocked admission.
        // A later release phase permanently freezes both addition paths.
        room.setComposeApprovalRequired(true);
        room.setTeeIdentityApprovalRequired(true);
        room.freezeApprovalRequirements();
        require(room.dealCount() == 0, "diligence room must have no deployment-window deals");
        require(
            room.resultVerifier() == address(0) && room.pendingResultVerifier() == address(0)
                && room.pendingResultVerifierActivatesAt() == 0 && !room.resultVerifierFrozen(),
            "diligence result-verifier authority must start empty"
        );
        require(
            room.attestationVerifier() == address(0) && room.attestationReleasePolicyHash() == bytes32(0)
                && room.pendingAttestationVerifier() == address(0)
                && room.pendingAttestationReleasePolicyHash() == bytes32(0)
                && room.pendingAttestationBindingActivatesAt() == 0 && !room.attestationBindingFrozen(),
            "diligence QVL authority must start empty"
        );
        bytes32[3] memory emptyEvaluatorPolicies = room.evaluatorPolicies();
        require(
            room.approvedEvaluatorPolicyCount() == 0 && room.pendingEvaluatorPolicyCount() == 0
                && !room.evaluatorPolicySetFrozen() && room.evaluatorPolicySetRoot() == bytes32(0)
                && emptyEvaluatorPolicies[0] == bytes32(0) && emptyEvaluatorPolicies[1] == bytes32(0)
                && emptyEvaluatorPolicies[2] == bytes32(0),
            "diligence evaluator-policy authority must start empty"
        );

        encumbrance =
            new TinkerAccountEncumbrance(operator, accountCommitment, bytes32(0), maxAddBalanceWei, maxSpendWei);
        // Fresh encumbrance releases are halted. Both authority sets start
        // empty; an exact account/caps/compose/manager policy must complete the
        // separate two-day activation ceremony before operations.
        require(encumbrance.emergencyHalted(), "encumbrance must deploy halted");
        require(!encumbrance.releasePolicyFrozen(), "encumbrance policy unexpectedly frozen");
        require(encumbrance.approvedComposeCount() == 0, "encumbrance compose authority must start empty");
        require(encumbrance.managerCount() == 0, "encumbrance manager authority must start empty");

        // The royalty rail is intentionally fail-closed at deployment. The
        // exact settlement-CVM/QVL/ExecutionPolicyAnchor binding completes a
        // separate two-day release ceremony after final CVM measurement.
        royalties = new RoyaltyDistributor(operator);
        require(royalties.owner() == operator, "royalty owner mismatch");
        require(royalties.paused(), "royalty distributor must deploy paused");
        require(royalties.releasePolicyCommitment() == bytes32(0), "royalty authority must start empty");
        challenges = new ChallengeRegistry(operator);
        computeVault = new ComputeCreditVault(operator, computeDeveloper, reviewedComputeDeveloperFeeBps);
        // The fee embedded into every future timelocked rate-policy commitment
        // is fixed at deployment. Asset, rate, compose, and TEE admission stay
        // empty until their separate post-attestation governance phase.
        computeVault.freezeDeveloperFee();
        // Deliberately deploy deny-all. The final oracle compose hash, device
        // policy, and consumer bindings are governance actions performed only
        // after the replacement CVMs and their attestations have been checked.
        emailOracleAuth = new EmailOracleAuth(operator, emailOracleUpgradeDelay, false, bytes32(0), bytes32(0), true);
        require(emailOracleAuth.productionRelease(), "email oracle auth must deploy in production mode");
        // A fresh anchor cannot write until the final CVM-controlled writer and
        // its exact release commitment complete the separate two-day admission
        // ceremony. It starts paused and contains no implicit operator writer.
        executionPolicyAnchor =
            new ExecutionPolicyAnchor(operator, deploymentIntentSha256, reviewerAuthorityGenesisAcceptanceSha256);

        vm.stopBroadcast();

        console.log("DiligenceRoom:", address(room));
        console.log("TinkerAccountEncumbrance:", address(encumbrance));
        console.log("RoyaltyDistributor:", address(royalties));
        console.log("ChallengeRegistry:", address(challenges));
        console.log("ComputeCreditVault:", address(computeVault));
        console.log("EmailOracleAuth:", address(emailOracleAuth));
        console.log("ExecutionPolicyAnchor:", address(executionPolicyAnchor));
        console.log("Operator:", operator);
        console.log("Diligence governance controller:", diligenceGovernanceController);
        console.log("Result verifier (post-deploy):", room.resultVerifier());
        console.log("Compute developer:", computeDeveloper);
        console.log("Compute developer fee bps:", computeDeveloperFeeBps);
        console.log("Email oracle upgrade delay:", emailOracleUpgradeDelay);
    }

    function _reviewedComputeDeveloperFee(uint256 computeDeveloperFeeBps) internal pure returns (uint16) {
        require(
            computeDeveloperFeeBps <= MAX_FRESH_RELEASE_DEVELOPER_FEE_BPS && computeDeveloperFeeBps <= type(uint16).max,
            "compute developer fee exceeds fresh-release cap"
        );
        // The explicit fresh-release cap above makes this narrowing exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint16(computeDeveloperFeeBps);
    }
}
