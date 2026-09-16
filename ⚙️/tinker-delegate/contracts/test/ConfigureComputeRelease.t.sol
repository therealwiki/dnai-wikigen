// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ConfigureComputeReleaseScript} from "../script/ConfigureComputeRelease.s.sol";
import {ComputeCreditVault} from "../src/ComputeCreditVault.sol";

contract CanonicalUsdcCodeStub {
    mapping(address => uint256) public balanceOf;
}

contract ConfigureComputeReleaseHarness is ConfigureComputeReleaseScript {
    function executeConfiguredPhase(uint256 phase, ReleaseInputs memory inputs) external {
        _executePhase(phase, inputs);
    }
}

contract ConfigureComputeReleaseTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    address internal constant BASE_SEPOLIA_USDC = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    ConfigureComputeReleaseHarness internal script;
    ComputeCreditVault internal vault;
    address internal operator;
    address internal developer = makeAddr("compute-developer");
    address internal meter = makeAddr("independent-meter");
    address internal meterQvl = makeAddr("independent-meter-qvl");
    address internal tee = makeAddr("compute-tee");
    address internal provider = makeAddr("compute-provider");
    bytes32 internal compose = keccak256("release-compose");
    bytes32 internal nativePolicy = keccak256("native-policy");
    bytes32 internal erc20Policy = keccak256("erc20-policy");
    bytes32 internal meteringPolicySetHash = keccak256("metering-policy-set");

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        vault = new ComputeCreditVault(operator, developer, 100);
        vm.prank(operator);
        vault.freezeDeveloperFee();
        CanonicalUsdcCodeStub stub = new CanonicalUsdcCodeStub();
        vm.etch(BASE_SEPOLIA_USDC, address(stub).code);

        script = new ConfigureComputeReleaseHarness();
    }

    function test_ThreeTimelockedPhasesProduceExactFrozenRelease() public {
        _runPhase(1);
        assertEq(vault.pendingAssetCount(), 1);
        assertEq(vault.pendingRatePolicyCount(), 1);
        assertEq(vault.pendingComposeCount(), 1);
        assertEq(vault.pendingMeteringVerifier(), meter);
        assertEq(vault.pendingMeteringQvlVerifier(), meterQvl);
        assertEq(vault.pendingMeteringPolicySetHash(), meteringPolicySetHash);
        assertGt(vault.pendingAssetActivations(BASE_SEPOLIA_USDC), block.timestamp);
        assertGt(vault.pendingComposeActivations(compose), block.timestamp);

        vm.warp(vault.pendingAssetActivations(BASE_SEPOLIA_USDC));
        _runPhase(2);
        assertEq(vault.allowedAssetCount(), 1);
        assertEq(vault.activeRatePolicyCount(), 1);
        assertEq(vault.approvedComposeCount(), 1);
        assertEq(vault.approvedTeeIdentityCount(), 0);
        assertEq(vault.pendingAssetCount(), 0);
        assertEq(vault.pendingRatePolicyCount(), 1);
        assertEq(vault.pendingComposeCount(), 0);
        assertEq(vault.pendingTeeIdentityCount(), 1);
        assertEq(vault.meteringVerifier(), meter);
        assertEq(vault.meteringQvlVerifier(), meterQvl);
        assertEq(vault.meteringPolicySetHash(), meteringPolicySetHash);
        assertTrue(vault.meteringBindingFrozen());

        (,,, uint64 erc20ActivatesAt) = vault.pendingRatePolicies(erc20Policy);
        uint64 teeActivatesAt = vault.pendingTeeIdentityActivations(tee);
        vm.warp(erc20ActivatesAt > teeActivatesAt ? erc20ActivatesAt : teeActivatesAt);
        _runPhase(3);
        assertEq(vault.allowedAssetCount(), 1);
        assertEq(vault.activeRatePolicyCount(), 2);
        assertEq(vault.approvedComposeCount(), 1);
        assertEq(vault.approvedTeeIdentityCount(), 1);
        assertEq(vault.pendingAssetCount(), 0);
        assertEq(vault.pendingRatePolicyCount(), 0);
        assertEq(vault.pendingComposeCount(), 0);
        assertEq(vault.pendingTeeIdentityCount(), 0);
        assertTrue(vault.assetAdditionsFrozen());
        assertTrue(vault.ratePolicyAdditionsFrozen());
        assertTrue(vault.composePolicyFrozen());
        assertTrue(vault.teeIdentityAdditionsFrozen());
        assertFalse(vault.paused());
        assertEq(vault.teeIdentityComposeHash(tee), compose);
    }

    function test_CannotSkipTimelocksOrReplayAPhase() public {
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 admission state"));
        _runPhase(2);

        _runPhase(1);
        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-admission vault"));
        _runPhase(1);
        vm.expectRevert(bytes("USDC timelock has not elapsed"));
        _runPhase(2);
    }

    function test_ExtraActivatedAdmissionBlocksFinalFreeze() public {
        _runPhase(1);
        vm.warp(vault.pendingAssetActivations(BASE_SEPOLIA_USDC));
        _runPhase(2);

        bytes32 extraCompose = keccak256("unreviewed-compose");
        vm.prank(operator);
        vault.proposeComposeHash(extraCompose);
        (,,, uint64 extraComposeActivatesAt) = vault.pendingRatePolicies(erc20Policy);
        uint64 proposedComposeActivatesAt = vault.pendingComposeActivations(extraCompose);
        vm.warp(
            extraComposeActivatesAt > proposedComposeActivatesAt ? extraComposeActivatesAt : proposedComposeActivatesAt
        );
        vm.prank(operator);
        vault.activateComposeHash(extraCompose);

        vm.expectRevert(bytes("phase 3 requires the exact phase-2 admission state"));
        _runPhase(3);
        assertFalse(vault.composePolicyFrozen());
        assertFalse(vault.ratePolicyAdditionsFrozen());
        assertFalse(vault.assetAdditionsFrozen());
    }

    function test_SurplusPendingAssetBlocksPhaseOne() public {
        CanonicalUsdcCodeStub extraAsset = new CanonicalUsdcCodeStub();
        vm.prank(operator);
        vault.proposeAsset(address(extraAsset));

        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-admission vault"));
        _runPhase(1);
    }

    function test_RuntimeCodeHashMustMatchTheReviewedFreshVault() public {
        ConfigureComputeReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.vaultRuntimeCodeHash = keccak256("wrong-runtime");
        vm.expectRevert(bytes("ComputeCreditVault runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);
    }

    function test_ReleaseInputsRejectControlRoleCollisions() public {
        ConfigureComputeReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.operator = makeAddr("wrong-operator");
        vm.expectRevert(bytes("operator does not own ComputeCreditVault"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.teeIdentity = developer;
        vm.expectRevert(bytes("compute TEE conflicts with a control role"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.nativeProvider = meter;
        vm.expectRevert(bytes("native provider conflicts with a control role"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.erc20Provider = tee;
        vm.expectRevert(bytes("USDC provider conflicts with a control role"));
        script.executeConfiguredPhase(1, inputs);
    }

    function test_SurplusPendingRatePolicyBlocksPhaseOne() public {
        vm.prank(operator);
        vault.proposeRatePolicy(keccak256("unreviewed-rate"), address(0), makeAddr("extra-provider"), 100);

        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-admission vault"));
        _runPhase(1);
    }

    function test_SurplusPendingComposeBlocksPhaseOne() public {
        vm.prank(operator);
        vault.proposeComposeHash(keccak256("unreviewed-pending-compose"));

        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-admission vault"));
        _runPhase(1);
    }

    function test_HistoricalExtraTeeAdmissionBlocksPhaseOne() public {
        bytes32 historicalCompose = keccak256("historical-compose");
        address historicalTee = makeAddr("historical-tee");
        vm.prank(operator);
        vault.proposeComposeHash(historicalCompose);
        vm.warp(vault.pendingComposeActivations(historicalCompose));
        vm.startPrank(operator);
        vault.activateComposeHash(historicalCompose);
        vault.proposeTeeIdentity(historicalTee, historicalCompose);
        vm.warp(vault.pendingTeeIdentityActivations(historicalTee));
        vault.activateTeeIdentity(historicalTee);
        vault.revokeComposeHash(historicalCompose);
        vm.stopPrank();

        assertEq(vault.approvedComposeCount(), 0);
        assertEq(vault.approvedTeeIdentityCount(), 1);
        vm.expectRevert(bytes("phase 1 requires the exact fresh empty-admission vault"));
        _runPhase(1);
    }

    function test_SurplusTeeAdmissionBlocksFinalFreeze() public {
        _runPhase(1);
        vm.warp(vault.pendingAssetActivations(BASE_SEPOLIA_USDC));
        _runPhase(2);
        vm.prank(operator);
        vault.proposeTeeIdentity(makeAddr("unreviewed-tee"), compose);

        (,,, uint64 erc20ActivatesAt) = vault.pendingRatePolicies(erc20Policy);
        uint64 teeActivatesAt = vault.pendingTeeIdentityActivations(tee);
        vm.warp(erc20ActivatesAt > teeActivatesAt ? erc20ActivatesAt : teeActivatesAt);
        vm.expectRevert(bytes("phase 3 requires the exact phase-2 admission state"));
        _runPhase(3);
    }

    function test_ProviderInputsMustMatchTheTimelockedPolicies() public {
        _runPhase(1);
        vm.warp(vault.pendingAssetActivations(BASE_SEPOLIA_USDC));
        ConfigureComputeReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.nativeProvider = makeAddr("wrong-native-provider");
        vm.expectRevert(bytes("pending rate-policy provider mismatch"));
        script.executeConfiguredPhase(2, inputs);

        _runPhase(2);
        (,,, uint64 erc20ActivatesAt) = vault.pendingRatePolicies(erc20Policy);
        vm.warp(erc20ActivatesAt);
        inputs = _inputs();
        inputs.erc20Provider = makeAddr("wrong-erc20-provider");
        vm.expectRevert(bytes("pending rate-policy provider mismatch"));
        script.executeConfiguredPhase(3, inputs);
    }

    function _runPhase(uint256 phase) internal {
        script.executeConfiguredPhase(phase, _inputs());
    }

    function _inputs() internal view returns (ConfigureComputeReleaseScript.ReleaseInputs memory) {
        return ConfigureComputeReleaseScript.ReleaseInputs({
            vault: vault,
            vaultRuntimeCodeHash: address(vault).codehash,
            operator: operator,
            teeIdentity: tee,
            composeHash: compose,
            nativePolicy: nativePolicy,
            erc20Policy: erc20Policy,
            nativeProvider: provider,
            erc20Provider: provider,
            meteringVerifier: meter,
            meteringQvlVerifier: meterQvl,
            meteringPolicySetHash: meteringPolicySetHash
        });
    }
}
