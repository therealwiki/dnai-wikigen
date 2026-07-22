// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

/// @notice Two-phase, fail-closed activation of the exact production Tinker policy.
/// @dev A fresh encumbrance is halted. Phase 1 stages the reviewed account,
///      per-operation caps, compose set, and optional delegated manager. Phase 2
///      activates that exact commitment after the review delay and permanently
///      closes every authority-increasing path.
contract ConfigureTinkerReleaseScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    struct ReleaseInputs {
        TinkerAccountEncumbrance encumbrance;
        bytes32 encumbranceRuntimeCodeHash;
        address operator;
        bytes32 accountCommitment;
        uint256 maxAddBalanceWei;
        uint256 maxSpendWei;
        bytes32 composeHash;
        address manager;
    }

    function run() public {
        _runPhase(vm.envUint("TINKER_ENCUMBRANCE_RELEASE_PHASE"));
    }

    /// @notice Explicit selector for deterministic rehearsals. It performs the
    ///         same checks and broadcasts as the environment-driven `run()`.
    function runPhase(uint256 phase) public {
        _runPhase(phase);
    }

    function _runPhase(uint256 phase) internal {
        ReleaseInputs memory inputs = ReleaseInputs({
            encumbrance: TinkerAccountEncumbrance(vm.envAddress("TINKER_ENCUMBRANCE_ADDRESS")),
            encumbranceRuntimeCodeHash: vm.envBytes32("TINKER_ENCUMBRANCE_RUNTIME_CODE_HASH"),
            operator: vm.envAddress("DEPLOYMENT_OPERATOR"),
            accountCommitment: vm.envBytes32("TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT"),
            maxAddBalanceWei: vm.envUint("TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI"),
            maxSpendWei: vm.envUint("TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI"),
            composeHash: vm.envBytes32("TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH"),
            manager: vm.envAddress("TINKER_ENCUMBRANCE_RELEASE_MANAGER")
        });
        _executePhase(phase, inputs);
    }

    function _executePhase(uint256 phase, ReleaseInputs memory inputs) internal {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "tinker release is Base Sepolia only");
        _requireCommonReleaseInputs(inputs);

        bytes32[] memory composeSet = _composeSet(inputs.composeHash);
        address[] memory managerSet = _managerSet(inputs.manager);
        bytes32 composeRoot = inputs.encumbrance.computeComposeRoot(composeSet);
        bytes32 managerRoot = inputs.encumbrance.computeManagerRoot(managerSet);
        bytes32 releaseCommitment = inputs.encumbrance
            .computeReleasePolicyCommitment(
                inputs.accountCommitment,
                inputs.maxAddBalanceWei,
                inputs.maxSpendWei,
                composeRoot,
                composeSet.length,
                managerRoot,
                managerSet.length
            );

        if (phase == 1) {
            _phaseOne(inputs, composeSet, composeRoot, managerRoot, releaseCommitment);
        } else if (phase == 2) {
            _phaseTwo(inputs, composeRoot, managerRoot, releaseCommitment);
        } else {
            revert("TINKER_ENCUMBRANCE_RELEASE_PHASE must be 1 or 2");
        }

        console.log("Tinker release phase:", phase);
        console.log("TinkerAccountEncumbrance:", address(inputs.encumbrance));
        console.log("Release policy frozen:", inputs.encumbrance.releasePolicyFrozen());
        console.log("Emergency halted:", inputs.encumbrance.emergencyHalted());
        console.log("Approved compose hashes:", inputs.encumbrance.approvedComposeCount());
        console.log("Approved managers:", inputs.encumbrance.managerCount());
        console.log("Pending compose hashes:", inputs.encumbrance.pendingComposeCount());
        console.log("Pending managers:", inputs.encumbrance.pendingManagerCount());
    }

    function _requireCommonReleaseInputs(ReleaseInputs memory inputs) internal view {
        TinkerAccountEncumbrance encumbrance = inputs.encumbrance;
        require(
            inputs.encumbranceRuntimeCodeHash != bytes32(0)
                && address(encumbrance).codehash == inputs.encumbranceRuntimeCodeHash,
            "TinkerAccountEncumbrance runtime code hash mismatch"
        );
        require(
            inputs.operator != address(0) && encumbrance.owner() == inputs.operator,
            "operator does not own TinkerAccountEncumbrance"
        );
        require(inputs.operator != address(encumbrance), "operator cannot be the encumbrance");
        require(inputs.accountCommitment != bytes32(0), "release account commitment must be nonzero");
        require(
            inputs.maxAddBalanceWei != 0 && inputs.maxSpendWei != 0,
            "Tinker per-operation policy-unit caps must be nonzero"
        );
        require(inputs.maxSpendWei <= inputs.maxAddBalanceWei, "Tinker spend policy-unit cap exceeds add-balance cap");
        uint256 hardMaximum = encumbrance.MAX_POLICY_UNITS_PER_OPERATION();
        require(
            inputs.maxAddBalanceWei <= hardMaximum && inputs.maxSpendWei <= hardMaximum,
            "Tinker per-operation policy-unit cap exceeds hard maximum"
        );
        require(inputs.composeHash != bytes32(0), "release compose hash must be nonzero");
        require(encumbrance.emergencyHalted(), "TinkerAccountEncumbrance must remain halted until phase 2");
        require(encumbrance.pendingOwner() == address(0), "pending ownership transfer blocks release");
        if (inputs.manager != address(0)) {
            require(
                inputs.manager != inputs.operator && inputs.manager != address(encumbrance),
                "Tinker manager conflicts with a control role"
            );
        }
    }

    function _phaseOne(
        ReleaseInputs memory inputs,
        bytes32[] memory composeSet,
        bytes32 composeRoot,
        bytes32 managerRoot,
        bytes32 releaseCommitment
    ) internal {
        TinkerAccountEncumbrance encumbrance = inputs.encumbrance;
        require(
            !encumbrance.releasePolicyFrozen() && encumbrance.releasePolicyCommitment() == bytes32(0)
                && encumbrance.pendingReleasePolicyActivatesAt() == 0
                && encumbrance.pendingReleasePolicyCommitment() == bytes32(0) && encumbrance.pendingComposeCount() == 0
                && encumbrance.pendingManagerCount() == 0,
            "phase 1 requires no existing or pending release"
        );
        require(
            encumbrance.accountCommitment() == inputs.accountCommitment
                && encumbrance.maxAddBalanceWei() == inputs.maxAddBalanceWei
                && encumbrance.maxSpendWei() == inputs.maxSpendWei && encumbrance.approvedComposeCount() == 0
                && encumbrance.approvedComposeRoot() == encumbrance.computeComposeRoot(new bytes32[](0))
                && !encumbrance.approvedComposeHashes(inputs.composeHash) && encumbrance.managerCount() == 0
                && encumbrance.managerRoot() == encumbrance.computeManagerRoot(new address[](0)),
            "phase 1 requires the exact fresh halted draft"
        );

        address[] memory managerSet = _managerSet(inputs.manager);
        vm.startBroadcast();
        encumbrance.proposeReleasePolicy(
            inputs.accountCommitment, inputs.maxAddBalanceWei, inputs.maxSpendWei, composeSet, managerSet
        );
        vm.stopBroadcast();

        require(
            encumbrance.pendingAccountCommitment() == inputs.accountCommitment
                && encumbrance.pendingMaxAddBalanceWei() == inputs.maxAddBalanceWei
                && encumbrance.pendingMaxSpendWei() == inputs.maxSpendWei
                && encumbrance.pendingComposeRoot() == composeRoot && encumbrance.pendingManagerRoot() == managerRoot
                && encumbrance.pendingReleasePolicyCommitment() == releaseCommitment
                && encumbrance.pendingComposeCount() == 1 && encumbrance.pendingManagerCount() == managerSet.length
                && encumbrance.pendingComposeHashAt(0) == inputs.composeHash
                && encumbrance.pendingComposeApprovals(inputs.composeHash)
                && encumbrance.pendingReleasePolicyActivatesAt() > block.timestamp,
            "phase 1 did not stage the exact release policy"
        );
        if (inputs.manager != address(0)) {
            require(
                encumbrance.pendingManagerAt(0) == inputs.manager
                    && encumbrance.pendingManagerApprovals(inputs.manager),
                "phase 1 did not stage the exact manager"
            );
        }
    }

    function _phaseTwo(ReleaseInputs memory inputs, bytes32 composeRoot, bytes32 managerRoot, bytes32 releaseCommitment)
        internal
    {
        TinkerAccountEncumbrance encumbrance = inputs.encumbrance;
        uint256 expectedManagerCount = inputs.manager == address(0) ? 0 : 1;
        require(
            !encumbrance.releasePolicyFrozen() && encumbrance.releasePolicyCommitment() == bytes32(0)
                && encumbrance.pendingAccountCommitment() == inputs.accountCommitment
                && encumbrance.pendingMaxAddBalanceWei() == inputs.maxAddBalanceWei
                && encumbrance.pendingMaxSpendWei() == inputs.maxSpendWei
                && encumbrance.pendingComposeRoot() == composeRoot && encumbrance.pendingManagerRoot() == managerRoot
                && encumbrance.pendingReleasePolicyCommitment() == releaseCommitment
                && encumbrance.pendingComposeCount() == 1 && encumbrance.pendingManagerCount() == expectedManagerCount
                && encumbrance.pendingComposeHashAt(0) == inputs.composeHash
                && encumbrance.pendingComposeApprovals(inputs.composeHash),
            "phase 2 requires the exact phase-1 release proposal"
        );
        if (inputs.manager != address(0)) {
            require(
                encumbrance.pendingManagerAt(0) == inputs.manager
                    && encumbrance.pendingManagerApprovals(inputs.manager),
                "phase 2 manager proposal mismatch"
            );
        }
        uint64 activatesAt = encumbrance.pendingReleasePolicyActivatesAt();
        require(activatesAt != 0 && activatesAt <= block.timestamp, "Tinker release timelock has not elapsed");

        vm.startBroadcast();
        encumbrance.activateAndFreezeReleasePolicy();
        vm.stopBroadcast();

        require(
            encumbrance.releasePolicyFrozen() && !encumbrance.emergencyHalted()
                && encumbrance.releasePolicyCommitment() == releaseCommitment
                && encumbrance.accountCommitment() == inputs.accountCommitment
                && encumbrance.maxAddBalanceWei() == inputs.maxAddBalanceWei
                && encumbrance.maxSpendWei() == inputs.maxSpendWei
                && encumbrance.releaseMaxAddBalanceWei() == inputs.maxAddBalanceWei
                && encumbrance.releaseMaxSpendWei() == inputs.maxSpendWei
                && encumbrance.approvedComposeRoot() == composeRoot && encumbrance.approvedComposeCount() == 1
                && encumbrance.releaseComposeRoot() == composeRoot && encumbrance.releaseComposeCount() == 1
                && encumbrance.managerRoot() == managerRoot && encumbrance.managerCount() == expectedManagerCount
                && encumbrance.releaseManagerRoot() == managerRoot
                && encumbrance.releaseManagerCount() == expectedManagerCount
                && encumbrance.pendingReleasePolicyActivatesAt() == 0
                && encumbrance.pendingReleasePolicyCommitment() == bytes32(0) && encumbrance.pendingComposeCount() == 0
                && encumbrance.pendingManagerCount() == 0,
            "phase 2 did not freeze the exact release policy"
        );
        require(
            encumbrance.approvedComposeHashAt(0) == inputs.composeHash
                && encumbrance.approvedComposeHashes(inputs.composeHash),
            "phase 2 compose activation mismatch"
        );
        if (inputs.manager != address(0)) {
            require(
                encumbrance.managerAt(0) == inputs.manager && encumbrance.managers(inputs.manager),
                "phase 2 manager activation mismatch"
            );
        }
    }

    function _composeSet(bytes32 composeHash) internal pure returns (bytes32[] memory values) {
        values = new bytes32[](1);
        values[0] = composeHash;
    }

    function _managerSet(address manager) internal pure returns (address[] memory values) {
        values = new address[](manager == address(0) ? 0 : 1);
        if (manager != address(0)) values[0] = manager;
    }
}
