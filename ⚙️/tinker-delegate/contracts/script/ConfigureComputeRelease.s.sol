// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {ComputeCreditVault} from "../src/ComputeCreditVault.sol";

/// @notice Three-phase, fail-closed activation of the exact production compute policy.
/// @dev The vault deploys paused and without a metering verifier, avoiding a
///      circular dependency between its runtime bytecode and the QVL policy set.
///      Phase 1 stages every first-window admission, including the exact QVL
///      signer/policy-set hash. Phase 2 activates and freezes that binding, then
///      stages the USDC policy and TEE identity. Phase 3 activates the second
///      window, permanently closes every admission set, and only then unpauses.
contract ConfigureComputeReleaseScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    address internal constant BASE_SEPOLIA_USDC = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    struct ReleaseInputs {
        ComputeCreditVault vault;
        bytes32 vaultRuntimeCodeHash;
        address operator;
        address teeIdentity;
        bytes32 composeHash;
        bytes32 nativePolicy;
        bytes32 erc20Policy;
        address nativeProvider;
        address erc20Provider;
        address meteringVerifier;
        address meteringQvlVerifier;
        bytes32 meteringPolicySetHash;
    }

    function run() public {
        _runPhase(vm.envUint("COMPUTE_RELEASE_PHASE"));
    }

    /// @notice Explicit selector for deterministic rehearsals. It performs the
    ///         same checks and broadcasts as the environment-driven `run()`.
    function runPhase(uint256 phase) public {
        _runPhase(phase);
    }

    function _runPhase(uint256 phase) internal {
        ReleaseInputs memory inputs = ReleaseInputs({
            vault: ComputeCreditVault(payable(vm.envAddress("COMPUTE_VAULT_ADDRESS"))),
            vaultRuntimeCodeHash: vm.envBytes32("COMPUTE_VAULT_RUNTIME_CODE_HASH"),
            operator: vm.envAddress("DEPLOYMENT_OPERATOR"),
            teeIdentity: vm.envAddress("COMPUTE_VAULT_TEE_IDENTITY"),
            composeHash: vm.envBytes32("COMPUTE_VAULT_COMPOSE_HASH"),
            nativePolicy: vm.envBytes32("COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT"),
            erc20Policy: vm.envBytes32("COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT"),
            nativeProvider: vm.envAddress("COMPUTE_VAULT_NATIVE_PROVIDER"),
            erc20Provider: vm.envAddress("COMPUTE_VAULT_ERC20_PROVIDER"),
            meteringVerifier: vm.envAddress("COMPUTE_VAULT_METERING_VERIFIER"),
            meteringQvlVerifier: vm.envAddress("COMPUTE_VAULT_METERING_QVL_VERIFIER"),
            meteringPolicySetHash: vm.envBytes32("COMPUTE_METERING_POLICY_SET_HASH")
        });
        _executePhase(phase, inputs);
    }

    function _executePhase(uint256 phase, ReleaseInputs memory inputs) internal {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "compute release is Base Sepolia only");

        _requireCommonReleaseInputs(inputs);

        if (phase == 1) {
            _phaseOne(inputs);
        } else if (phase == 2) {
            _phaseTwo(inputs);
        } else if (phase == 3) {
            _phaseThree(inputs);
        } else {
            revert("COMPUTE_RELEASE_PHASE must be 1, 2, or 3");
        }

        console.log("Compute release phase:", phase);
        console.log("ComputeCreditVault:", address(inputs.vault));
        console.log("Allowed ERC20 assets:", inputs.vault.allowedAssetCount());
        console.log("Active rate policies:", inputs.vault.activeRatePolicyCount());
        console.log("Approved compose hashes:", inputs.vault.approvedComposeCount());
        console.log("Approved TEE identities:", inputs.vault.approvedTeeIdentityCount());
        console.log("Pending ERC20 assets:", inputs.vault.pendingAssetCount());
        console.log("Pending rate policies:", inputs.vault.pendingRatePolicyCount());
        console.log("Pending compose hashes:", inputs.vault.pendingComposeCount());
        console.log("Pending TEE identities:", inputs.vault.pendingTeeIdentityCount());
    }

    function _requireCommonReleaseInputs(ReleaseInputs memory inputs) internal view {
        ComputeCreditVault vault = inputs.vault;
        require(
            inputs.vaultRuntimeCodeHash != bytes32(0) && address(vault).codehash == inputs.vaultRuntimeCodeHash,
            "ComputeCreditVault runtime code hash mismatch"
        );
        require(
            inputs.operator != address(0) && vault.owner() == inputs.operator,
            "operator does not own ComputeCreditVault"
        );
        require(vault.developerFeeFrozen(), "compute developer fee is not frozen");
        require(vault.paused(), "ComputeCreditVault must remain paused until phase 3");
        require(inputs.teeIdentity != address(0), "compute TEE identity must be nonzero");
        require(inputs.composeHash != bytes32(0), "compute compose hash must be nonzero");
        require(inputs.nativePolicy != bytes32(0) && inputs.erc20Policy != bytes32(0), "rate policies must be nonzero");
        require(inputs.nativePolicy != inputs.erc20Policy, "native and USDC rate policies must differ");
        require(
            inputs.nativeProvider != address(0) && inputs.erc20Provider != address(0),
            "compute providers must be nonzero"
        );
        require(inputs.meteringVerifier != address(0), "metering verifier must be nonzero");
        require(inputs.meteringQvlVerifier != address(0), "metering QVL verifier must be nonzero");
        require(inputs.meteringVerifier != inputs.meteringQvlVerifier, "metering roles must be distinct");
        require(inputs.meteringPolicySetHash != bytes32(0), "metering policy-set hash must be nonzero");

        address developer = vault.developer();
        require(
            inputs.teeIdentity != inputs.operator && inputs.teeIdentity != developer
                && inputs.teeIdentity != inputs.meteringVerifier && inputs.teeIdentity != inputs.meteringQvlVerifier
                && inputs.teeIdentity != address(vault),
            "compute TEE conflicts with a control role"
        );
        require(
            inputs.nativeProvider != inputs.operator && inputs.nativeProvider != developer
                && inputs.nativeProvider != inputs.meteringVerifier
                && inputs.nativeProvider != inputs.meteringQvlVerifier && inputs.nativeProvider != inputs.teeIdentity
                && inputs.nativeProvider != address(vault),
            "native provider conflicts with a control role"
        );
        require(
            inputs.erc20Provider != inputs.operator && inputs.erc20Provider != developer
                && inputs.erc20Provider != inputs.meteringVerifier && inputs.erc20Provider != inputs.meteringQvlVerifier
                && inputs.erc20Provider != inputs.teeIdentity && inputs.erc20Provider != address(vault),
            "USDC provider conflicts with a control role"
        );
    }

    function _phaseOne(ReleaseInputs memory inputs) internal {
        ComputeCreditVault vault = inputs.vault;
        require(
            vault.allowedAssetCount() == 0 && vault.activeRatePolicyCount() == 0 && vault.approvedComposeCount() == 0
                && vault.approvedTeeIdentityCount() == 0 && vault.pendingAssetCount() == 0
                && vault.pendingRatePolicyCount() == 0 && vault.pendingComposeCount() == 0
                && vault.pendingTeeIdentityCount() == 0 && !vault.assetAdditionsFrozen()
                && !vault.ratePolicyAdditionsFrozen() && !vault.composePolicyFrozen()
                && !vault.teeIdentityAdditionsFrozen() && !vault.meteringBindingFrozen()
                && vault.meteringVerifier() == address(0) && vault.meteringQvlVerifier() == address(0)
                && vault.meteringPolicySetHash() == bytes32(0) && vault.pendingMeteringVerifier() == address(0)
                && vault.pendingMeteringQvlVerifier() == address(0)
                && vault.pendingMeteringPolicySetHash() == bytes32(0) && vault.pendingMeteringBindingActivatesAt() == 0,
            "phase 1 requires the exact fresh empty-admission vault"
        );
        require(!vault.allowedAssets(BASE_SEPOLIA_USDC), "canonical USDC is already allowed");
        require(vault.pendingAssetActivations(BASE_SEPOLIA_USDC) == 0, "canonical USDC proposal already exists");
        require(vault.pendingComposeActivations(inputs.composeHash) == 0, "compose proposal already exists");
        require(!vault.approvedComposeHashes(inputs.composeHash), "compose hash is already approved");
        require(!vault.ratePolicyEverConfigured(inputs.nativePolicy), "native rate policy was already configured");
        require(!vault.teeIdentityEverApproved(inputs.teeIdentity), "compute TEE has admission history");
        require(!vault.meteringVerifierEverConfigured(inputs.meteringVerifier), "metering verifier has binding history");
        require(
            !vault.meteringQvlVerifierEverConfigured(inputs.meteringQvlVerifier),
            "metering QVL verifier has binding history"
        );
        _requireNoPendingRatePolicy(vault, inputs.nativePolicy);

        vm.startBroadcast();
        vault.proposeAsset(BASE_SEPOLIA_USDC);
        vault.proposeRatePolicy(inputs.nativePolicy, address(0), inputs.nativeProvider, vault.developerFeeBps());
        vault.proposeComposeHash(inputs.composeHash);
        vault.proposeMeteringBinding(inputs.meteringVerifier, inputs.meteringQvlVerifier, inputs.meteringPolicySetHash);
        vm.stopBroadcast();

        require(vault.pendingAssetActivations(BASE_SEPOLIA_USDC) > block.timestamp, "USDC proposal was not staged");
        require(
            vault.pendingComposeActivations(inputs.composeHash) > block.timestamp, "compose proposal was not staged"
        );
        require(
            vault.pendingAssetCount() == 1 && vault.pendingRatePolicyCount() == 1 && vault.pendingComposeCount() == 1,
            "phase 1 did not stage the exact pending admission set"
        );
        require(
            vault.pendingMeteringVerifier() == inputs.meteringVerifier
                && vault.pendingMeteringQvlVerifier() == inputs.meteringQvlVerifier
                && vault.pendingMeteringPolicySetHash() == inputs.meteringPolicySetHash
                && vault.pendingMeteringBindingActivatesAt() > block.timestamp,
            "phase 1 did not stage the exact metering binding"
        );
        _requirePendingRatePolicy(vault, inputs.nativePolicy, address(0), inputs.nativeProvider, false);
    }

    function _phaseTwo(ReleaseInputs memory inputs) internal {
        ComputeCreditVault vault = inputs.vault;
        require(
            vault.allowedAssetCount() == 0 && vault.activeRatePolicyCount() == 0 && vault.approvedComposeCount() == 0
                && vault.approvedTeeIdentityCount() == 0 && vault.pendingAssetCount() == 1
                && vault.pendingRatePolicyCount() == 1 && vault.pendingComposeCount() == 1
                && vault.pendingTeeIdentityCount() == 0 && !vault.assetAdditionsFrozen()
                && !vault.ratePolicyAdditionsFrozen() && !vault.composePolicyFrozen()
                && !vault.teeIdentityAdditionsFrozen() && !vault.meteringBindingFrozen()
                && vault.meteringVerifier() == address(0) && vault.meteringQvlVerifier() == address(0)
                && vault.meteringPolicySetHash() == bytes32(0)
                && vault.pendingMeteringVerifier() == inputs.meteringVerifier
                && vault.pendingMeteringQvlVerifier() == inputs.meteringQvlVerifier
                && vault.pendingMeteringPolicySetHash() == inputs.meteringPolicySetHash,
            "phase 2 requires the exact phase-1 admission state"
        );
        uint64 assetActivatesAt = vault.pendingAssetActivations(BASE_SEPOLIA_USDC);
        uint64 composeActivatesAt = vault.pendingComposeActivations(inputs.composeHash);
        uint64 meterActivatesAt = vault.pendingMeteringBindingActivatesAt();
        require(assetActivatesAt != 0 && assetActivatesAt <= block.timestamp, "USDC timelock has not elapsed");
        require(composeActivatesAt != 0 && composeActivatesAt <= block.timestamp, "compose timelock has not elapsed");
        require(meterActivatesAt != 0 && meterActivatesAt <= block.timestamp, "metering timelock has not elapsed");
        _requirePendingRatePolicy(vault, inputs.nativePolicy, address(0), inputs.nativeProvider, true);
        _requireNoPendingRatePolicy(vault, inputs.erc20Policy);
        require(!vault.ratePolicyEverConfigured(inputs.erc20Policy), "USDC rate policy was already configured");

        vm.startBroadcast();
        vault.activateAsset(BASE_SEPOLIA_USDC);
        vault.activateRatePolicy(inputs.nativePolicy);
        vault.activateComposeHash(inputs.composeHash);
        vault.activateMeteringBinding();
        vault.freezeMeteringBinding();
        vault.proposeRatePolicy(inputs.erc20Policy, BASE_SEPOLIA_USDC, inputs.erc20Provider, vault.developerFeeBps());
        vault.proposeTeeIdentity(inputs.teeIdentity, inputs.composeHash);
        vm.stopBroadcast();

        require(
            vault.allowedAssetCount() == 1 && vault.activeRatePolicyCount() == 1 && vault.approvedComposeCount() == 1
                && vault.approvedTeeIdentityCount() == 0 && vault.pendingAssetCount() == 0
                && vault.pendingRatePolicyCount() == 1 && vault.pendingComposeCount() == 0
                && vault.pendingTeeIdentityCount() == 1 && vault.allowedAssets(BASE_SEPOLIA_USDC)
                && vault.approvedComposeHashes(inputs.composeHash) && vault.meteringBindingFrozen()
                && vault.meteringVerifier() == inputs.meteringVerifier
                && vault.meteringQvlVerifier() == inputs.meteringQvlVerifier
                && vault.meteringPolicySetHash() == inputs.meteringPolicySetHash
                && vault.pendingMeteringBindingActivatesAt() == 0,
            "phase 2 did not create the exact intermediate admission state"
        );
        require(
            vault.pendingTeeIdentityComposeHash(inputs.teeIdentity) == inputs.composeHash
                && vault.pendingTeeIdentityActivations(inputs.teeIdentity) > block.timestamp,
            "phase 2 did not stage the exact TEE identity"
        );
        _requireActiveRatePolicy(vault, inputs.nativePolicy, address(0), inputs.nativeProvider);
        _requirePendingRatePolicy(vault, inputs.erc20Policy, BASE_SEPOLIA_USDC, inputs.erc20Provider, false);
    }

    function _phaseThree(ReleaseInputs memory inputs) internal {
        ComputeCreditVault vault = inputs.vault;
        require(
            vault.allowedAssetCount() == 1 && vault.activeRatePolicyCount() == 1 && vault.approvedComposeCount() == 1
                && vault.approvedTeeIdentityCount() == 0 && vault.pendingAssetCount() == 0
                && vault.pendingRatePolicyCount() == 1 && vault.pendingComposeCount() == 0
                && vault.pendingTeeIdentityCount() == 1 && vault.allowedAssets(BASE_SEPOLIA_USDC)
                && vault.approvedComposeHashes(inputs.composeHash) && !vault.assetAdditionsFrozen()
                && !vault.ratePolicyAdditionsFrozen() && !vault.composePolicyFrozen()
                && !vault.teeIdentityAdditionsFrozen() && vault.meteringBindingFrozen()
                && vault.meteringVerifier() == inputs.meteringVerifier
                && vault.meteringQvlVerifier() == inputs.meteringQvlVerifier
                && vault.meteringPolicySetHash() == inputs.meteringPolicySetHash
                && vault.pendingMeteringBindingActivatesAt() == 0,
            "phase 3 requires the exact phase-2 admission state"
        );
        _requireActiveRatePolicy(vault, inputs.nativePolicy, address(0), inputs.nativeProvider);
        _requirePendingRatePolicy(vault, inputs.erc20Policy, BASE_SEPOLIA_USDC, inputs.erc20Provider, true);
        require(vault.teeIdentityComposeHash(inputs.teeIdentity) == bytes32(0), "compute TEE is already bound");
        require(
            vault.pendingTeeIdentityComposeHash(inputs.teeIdentity) == inputs.composeHash,
            "pending compute TEE compose mismatch"
        );
        uint64 teeActivatesAt = vault.pendingTeeIdentityActivations(inputs.teeIdentity);
        require(teeActivatesAt != 0 && teeActivatesAt <= block.timestamp, "TEE identity timelock has not elapsed");

        vm.startBroadcast();
        vault.activateRatePolicy(inputs.erc20Policy);
        vault.activateTeeIdentity(inputs.teeIdentity);
        vault.freezeAssetAdditions();
        vault.freezeRatePolicyAdditions();
        vault.freezeComposePolicy();
        vault.freezeTeeIdentityAdditions();
        vault.setPaused(false);
        vm.stopBroadcast();

        require(
            vault.allowedAssetCount() == 1 && vault.activeRatePolicyCount() == 2 && vault.approvedComposeCount() == 1
                && vault.approvedTeeIdentityCount() == 1 && vault.pendingAssetCount() == 0
                && vault.pendingRatePolicyCount() == 0 && vault.pendingComposeCount() == 0
                && vault.pendingTeeIdentityCount() == 0 && vault.assetAdditionsFrozen()
                && vault.ratePolicyAdditionsFrozen() && vault.composePolicyFrozen()
                && vault.teeIdentityAdditionsFrozen() && vault.meteringBindingFrozen() && !vault.paused()
                && vault.teeIdentityComposeHash(inputs.teeIdentity) == inputs.composeHash,
            "phase 3 did not close the exact compute release policy"
        );
        _requireActiveRatePolicy(vault, inputs.nativePolicy, address(0), inputs.nativeProvider);
        _requireActiveRatePolicy(vault, inputs.erc20Policy, BASE_SEPOLIA_USDC, inputs.erc20Provider);
    }

    function _requireNoPendingRatePolicy(ComputeCreditVault vault, bytes32 commitment) internal view {
        (address asset, address provider, uint16 feeBps, uint64 activatesAt) = vault.pendingRatePolicies(commitment);
        require(
            asset == address(0) && provider == address(0) && feeBps == 0 && activatesAt == 0,
            "unexpected pending rate policy"
        );
    }

    function _requirePendingRatePolicy(
        ComputeCreditVault vault,
        bytes32 commitment,
        address expectedAsset,
        address expectedProvider,
        bool requireElapsed
    ) internal view {
        (address asset, address provider, uint16 feeBps, uint64 activatesAt) = vault.pendingRatePolicies(commitment);
        require(asset == expectedAsset, "pending rate-policy asset mismatch");
        if (expectedProvider != address(0)) {
            require(provider == expectedProvider, "pending rate-policy provider mismatch");
        }
        require(provider != address(0), "pending rate-policy provider is zero");
        require(feeBps == vault.developerFeeBps(), "pending rate-policy fee mismatch");
        require(activatesAt != 0, "rate-policy proposal is missing");
        if (requireElapsed) require(activatesAt <= block.timestamp, "rate-policy timelock has not elapsed");
        else require(activatesAt > block.timestamp, "rate-policy proposal is not freshly timelocked");
    }

    function _requireActiveRatePolicy(
        ComputeCreditVault vault,
        bytes32 commitment,
        address expectedAsset,
        address expectedProvider
    ) internal view {
        (address asset, address provider, uint16 feeBps, bool active) = vault.ratePolicies(commitment);
        require(
            active && asset == expectedAsset && provider == expectedProvider && feeBps == vault.developerFeeBps(),
            "active rate policy does not match the release"
        );
    }
}
