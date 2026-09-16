// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {DiligenceRoomScript} from "../script/DiligenceRoom.s.sol";
import {TinkerAccountEncumbranceScript} from "../script/TinkerAccountEncumbrance.s.sol";
import {ComputeCreditVault} from "../src/ComputeCreditVault.sol";

contract SecurityAuditTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 internal constant BASE_MAINNET_CHAIN_ID = 8453;

    address internal owner = makeAddr("audit-owner");
    address internal developer = makeAddr("audit-developer");
    address internal provider = makeAddr("audit-provider");
    bytes32 internal constant NATIVE_POLICY = keccak256("audit-native-policy");

    function test_RatePolicyAdmissionRequiresFrozenDeveloperFee() public {
        ComputeCreditVault vault = new ComputeCreditVault(owner, developer, 500);

        vm.startPrank(owner);
        vm.expectRevert(ComputeCreditVault.DeveloperFeeNotFrozen.selector);
        vault.proposeRatePolicy(NATIVE_POLICY, address(0), provider, 500);
        vault.freezeDeveloperFee();
        vault.proposeRatePolicy(NATIVE_POLICY, address(0), provider, 500);
        vm.expectRevert(ComputeCreditVault.GovernanceFrozen.selector);
        vault.proposeDeveloperFee(600);
        vm.stopPrank();

        (address asset, address configuredProvider, uint16 policyFee, uint64 activatesAt) =
            vault.pendingRatePolicies(NATIVE_POLICY);
        assertEq(asset, address(0));
        assertEq(configuredProvider, provider);
        assertEq(policyFee, 500);
        assertGt(activatesAt, block.timestamp);
        assertEq(vault.developerFeeBps(), 500);
        assertTrue(vault.developerFeeFrozen());
    }

    function test_StandaloneDiligenceHelperRejectsBaseSepolia() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        vm.setEnv("DEPLOYMENT_OPERATOR", vm.toString(msg.sender));
        vm.setEnv("DILIGENCE_RESULT_VERIFIER", vm.toString(makeAddr("audit-result-verifier")));

        DiligenceRoomScript standalone = new DiligenceRoomScript();
        vm.expectRevert(bytes("use DeployFreshSuite for Base DiligenceRoom releases"));
        standalone.run();
    }

    function test_StandaloneDiligenceHelperRemainsAvailableForLocalDevelopment() public {
        vm.chainId(31337);
        vm.setEnv("DEPLOYMENT_OPERATOR", vm.toString(msg.sender));
        vm.setEnv("DILIGENCE_RESULT_VERIFIER", vm.toString(makeAddr("audit-local-result-verifier")));

        DiligenceRoomScript standalone = new DiligenceRoomScript();
        standalone.run();
    }

    function test_StandaloneTinkerHelperRejectsBaseNetworks() public {
        TinkerAccountEncumbranceScript standalone = new TinkerAccountEncumbranceScript();
        bytes memory expectedRevert = bytes("use DeployFreshSuite for Base TinkerAccountEncumbrance releases");

        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        vm.expectRevert(expectedRevert);
        standalone.run();

        vm.chainId(BASE_MAINNET_CHAIN_ID);
        vm.expectRevert(expectedRevert);
        standalone.run();
    }

    function test_StandaloneTinkerHelperRemainsAvailableForLocalDevelopment() public {
        vm.chainId(31337);
        vm.setEnv("TINKER_ENCUMBRANCE_OWNER", vm.toString(msg.sender));
        vm.setEnv("TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT", vm.toString(keccak256("audit-tinker-account")));
        vm.setEnv("TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH", vm.toString(keccak256("audit-tinker-compose")));
        vm.setEnv("TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI", "10000000000000000000");
        vm.setEnv("TINKER_ENCUMBRANCE_MAX_SPEND_WEI", "10000000000000000000");

        TinkerAccountEncumbranceScript standalone = new TinkerAccountEncumbranceScript();
        standalone.run();
    }
}
