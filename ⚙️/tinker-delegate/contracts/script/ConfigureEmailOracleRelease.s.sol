// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {EmailOracleAuth} from "../src/EmailOracleAuth.sol";
import {IAppAuth} from "../src/interfaces/IAppAuth.sol";

/// @notice Four-phase Base Sepolia ceremony for one exact email-oracle release.
/// @dev Registration with the verified dstack KMS and collection of the
///      independently QVL-verified restart/key-derivation evidence occur between
///      phases 2 and 3. Phase 3 commits that external evidence on-chain; phase 4
///      rechecks KMS registration and target boot authorization after the full
///      immutable delay before closing every addition path.
contract ConfigureEmailOracleReleaseScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    struct ReleaseInputs {
        EmailOracleAuth auth;
        bytes32 authRuntimeCodeHash;
        address operator;
        bytes32 oracleComposeHash;
        bytes32 deviceId;
        address consumerAppId;
        bytes32 consumerComposeHash;
        address kmsContract;
        bytes32 kmsRuntimeCodeHash;
        address kmsImplementation;
        bytes32 kmsImplementationRuntimeCodeHash;
        bytes32 kmsRegistrationTxHash;
        uint64 kmsRegistrationBlock;
        bytes32 kmsRegistrationBlockHash;
        IAppAuth.AppBootInfo targetBootInfo;
        bytes32 restartKeyDerivationProofHash;
    }

    function run() public {
        _runPhase(vm.envUint("EMAIL_ORACLE_RELEASE_PHASE"));
    }

    function runPhase(uint256 phase) public {
        _runPhase(phase);
    }

    function _runPhase(uint256 phase) internal {
        EmailOracleAuth auth = EmailOracleAuth(vm.envAddress("EMAIL_ORACLE_AUTH_ADDRESS"));
        bytes32 oracleComposeHash = vm.envBytes32("EMAIL_ORACLE_COMPOSE_HASH");
        bytes32 deviceId = vm.envBytes32("EMAIL_ORACLE_DEVICE_ID");
        ReleaseInputs memory inputs = ReleaseInputs({
            auth: auth,
            authRuntimeCodeHash: vm.envBytes32("EMAIL_ORACLE_RUNTIME_CODE_HASH"),
            operator: vm.envAddress("DEPLOYMENT_OPERATOR"),
            oracleComposeHash: oracleComposeHash,
            deviceId: deviceId,
            consumerAppId: vm.envAddress("EMAIL_ORACLE_CONSUMER_APP_ID"),
            consumerComposeHash: vm.envBytes32("EMAIL_ORACLE_CONSUMER_COMPOSE_HASH"),
            kmsContract: address(0),
            kmsRuntimeCodeHash: bytes32(0),
            kmsImplementation: address(0),
            kmsImplementationRuntimeCodeHash: bytes32(0),
            kmsRegistrationTxHash: bytes32(0),
            kmsRegistrationBlock: 0,
            kmsRegistrationBlockHash: bytes32(0),
            targetBootInfo: _emptyBootInfo(),
            restartKeyDerivationProofHash: bytes32(0)
        });
        if (phase >= 3) {
            string[] memory advisoryIds = new string[](0);
            inputs.kmsContract = vm.envAddress("EMAIL_ORACLE_KMS_ADDRESS");
            inputs.kmsRuntimeCodeHash = vm.envBytes32("EMAIL_ORACLE_KMS_RUNTIME_CODE_HASH");
            inputs.kmsImplementation = vm.envAddress("EMAIL_ORACLE_KMS_IMPLEMENTATION_ADDRESS");
            inputs.kmsImplementationRuntimeCodeHash = vm.envBytes32("EMAIL_ORACLE_KMS_IMPLEMENTATION_RUNTIME_CODE_HASH");
            inputs.kmsRegistrationTxHash = vm.envBytes32("EMAIL_ORACLE_KMS_REGISTRATION_TX_HASH");
            inputs.kmsRegistrationBlock = uint64(vm.envUint("EMAIL_ORACLE_KMS_REGISTRATION_BLOCK"));
            inputs.kmsRegistrationBlockHash = vm.envBytes32("EMAIL_ORACLE_KMS_REGISTRATION_BLOCK_HASH");
            inputs.restartKeyDerivationProofHash = vm.envBytes32("EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256");
            inputs.targetBootInfo = IAppAuth.AppBootInfo({
                appId: address(auth),
                composeHash: oracleComposeHash,
                instanceId: vm.envAddress("EMAIL_ORACLE_BOOT_INSTANCE_ID"),
                deviceId: deviceId,
                mrAggregated: vm.envBytes32("EMAIL_ORACLE_BOOT_MR_AGGREGATED"),
                mrSystem: vm.envBytes32("EMAIL_ORACLE_BOOT_MR_SYSTEM"),
                osImageHash: vm.envBytes32("EMAIL_ORACLE_BOOT_OS_IMAGE_HASH"),
                tcbStatus: "UpToDate",
                advisoryIds: advisoryIds
            });
        }
        _executePhase(phase, inputs);
    }

    function _emptyBootInfo() private pure returns (IAppAuth.AppBootInfo memory info) {
        info.advisoryIds = new string[](0);
    }

    function _executePhase(uint256 phase, ReleaseInputs memory inputs) internal {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "email release is Base Sepolia only");
        _requireCommonReleaseInputs(inputs);

        if (phase == 1) {
            _phaseOne(inputs);
        } else if (phase == 2) {
            _phaseTwo(inputs);
        } else if (phase == 3) {
            _phaseThree(inputs);
        } else if (phase == 4) {
            _phaseFour(inputs);
        } else {
            revert("EMAIL_ORACLE_RELEASE_PHASE must be 1, 2, 3, or 4");
        }

        console.log("Email oracle release phase:", phase);
        console.log("EmailOracleAuth:", address(inputs.auth));
        console.log("Active oracle compose hashes:", inputs.auth.allowedOracleComposeHashCount());
        console.log("Pending oracle compose hashes:", inputs.auth.pendingOracleComposeHashCount());
        console.log("Allowed devices:", inputs.auth.allowedDeviceIdCount());
        console.log("Consumer managers:", inputs.auth.consumerManagerCount());
        console.log("Consumer policies:", inputs.auth.totalConsumerComposeHashCount());
        console.log("Release ready:", inputs.auth.releaseConfigurationReady());
    }

    function _requireCommonReleaseInputs(ReleaseInputs memory inputs) internal view {
        EmailOracleAuth auth = inputs.auth;
        require(
            inputs.authRuntimeCodeHash != bytes32(0) && address(auth).codehash == inputs.authRuntimeCodeHash,
            "EmailOracleAuth runtime code hash mismatch"
        );
        require(
            inputs.operator != address(0) && auth.owner() == inputs.operator, "operator does not own EmailOracleAuth"
        );
        require(auth.pendingOwner() == address(0), "EmailOracleAuth has a pending owner");
        require(inputs.oracleComposeHash != bytes32(0), "oracle compose hash must be nonzero");
        require(inputs.deviceId != bytes32(0), "oracle device id must be nonzero");
        require(inputs.consumerAppId != address(0), "consumer app id must be nonzero");
        require(inputs.consumerComposeHash != bytes32(0), "consumer compose hash must be nonzero");
        require(
            inputs.consumerAppId != inputs.operator && inputs.consumerAppId != address(auth),
            "consumer app conflicts with a control role"
        );
        require(
            auth.ORACLE_UPGRADE_DELAY() >= auth.MIN_ORACLE_UPGRADE_DELAY()
                && auth.ORACLE_UPGRADE_DELAY() <= auth.MAX_ORACLE_UPGRADE_DELAY(),
            "oracle upgrade delay is outside release bounds"
        );
    }

    function _phaseOne(ReleaseInputs memory inputs) internal {
        EmailOracleAuth auth = inputs.auth;
        require(
            auth.productionRelease() && !auth.allowAnyDevice() && !auth.oracleCodeFrozen()
                && !auth.consumerRegistryFrozen() && !auth.consumerManagerAdditionsFrozen() && !auth.kmsBindingFrozen()
                && auth.allowedOracleComposeHashCount() == 0 && auth.pendingOracleComposeHashCount() == 0
                && auth.allowedDeviceIdCount() == 0 && auth.consumerManagerCount() == 0
                && auth.totalConsumerComposeHashCount() == 0 && auth.pendingKmsBindingActivatesAt() == 0,
            "phase 1 requires the exact fresh deny-all EmailOracleAuth"
        );

        vm.startBroadcast();
        auth.proposeOracleComposeHash(inputs.oracleComposeHash);
        auth.addDevice(inputs.deviceId);
        auth.setConsumerManager(inputs.consumerAppId, true);
        auth.addConsumerComposeHash(inputs.consumerAppId, inputs.consumerComposeHash);
        vm.stopBroadcast();

        require(
            auth.allowedOracleComposeHashCount() == 0 && auth.pendingOracleComposeHashCount() == 1
                && auth.pendingOracleComposeHashes(inputs.oracleComposeHash) > block.timestamp
                && auth.allowedDeviceIdCount() == 1 && auth.allowedDeviceIds(inputs.deviceId)
                && auth.consumerManagerCount() == 1 && auth.consumerManagers(inputs.consumerAppId)
                && auth.totalConsumerComposeHashCount() == 1 && auth.consumerComposeHashCount(inputs.consumerAppId) == 1
                && auth.isConsumerComposeHashRegistered(inputs.consumerAppId, inputs.consumerComposeHash)
                && !auth.isConsumerAuthorized(inputs.consumerAppId, inputs.consumerComposeHash),
            "phase 1 did not stage the exact oracle and consumer policy"
        );
    }

    function _phaseTwo(ReleaseInputs memory inputs) internal {
        EmailOracleAuth auth = inputs.auth;
        require(
            !auth.oracleCodeFrozen() && !auth.consumerRegistryFrozen() && !auth.consumerManagerAdditionsFrozen()
                && !auth.kmsBindingFrozen() && auth.allowedOracleComposeHashCount() == 0
                && auth.pendingOracleComposeHashCount() == 1 && auth.allowedDeviceIdCount() == 1
                && auth.consumerManagerCount() == 1 && auth.totalConsumerComposeHashCount() == 1
                && auth.allowedDeviceIds(inputs.deviceId) && auth.consumerManagers(inputs.consumerAppId)
                && auth.consumerComposeHashCount(inputs.consumerAppId) == 1
                && auth.isConsumerComposeHashRegistered(inputs.consumerAppId, inputs.consumerComposeHash)
                && !auth.isConsumerAuthorized(inputs.consumerAppId, inputs.consumerComposeHash)
                && auth.pendingKmsBindingActivatesAt() == 0,
            "phase 2 requires the exact phase-1 policy"
        );
        uint256 activatesAt = auth.pendingOracleComposeHashes(inputs.oracleComposeHash);
        require(activatesAt != 0 && activatesAt <= block.timestamp, "oracle compose timelock has not elapsed");

        vm.startBroadcast();
        auth.activateOracleComposeHash(inputs.oracleComposeHash);
        auth.freezeOracleCodeAuth(inputs.oracleComposeHash, inputs.deviceId);
        vm.stopBroadcast();

        require(
            auth.oracleCodeFrozen() && auth.allowedOracleComposeHashCount() == 1
                && auth.pendingOracleComposeHashCount() == 0
                && auth.allowedOracleComposeHashes(inputs.oracleComposeHash)
                && auth.releaseOracleComposeHash() == inputs.oracleComposeHash
                && auth.releaseDeviceId() == inputs.deviceId,
            "phase 2 did not freeze the exact oracle boot policy"
        );
    }

    function _phaseThree(ReleaseInputs memory inputs) internal {
        EmailOracleAuth auth = inputs.auth;
        _requireExactPhaseTwoState(inputs);
        _requireKmsEvidenceInputs(inputs);
        require(auth.pendingKmsBindingActivatesAt() == 0, "KMS binding proposal already exists");

        vm.startBroadcast();
        auth.proposeKmsBinding(
            inputs.kmsContract,
            inputs.kmsRuntimeCodeHash,
            inputs.kmsImplementation,
            inputs.kmsImplementationRuntimeCodeHash,
            inputs.kmsRegistrationTxHash,
            inputs.kmsRegistrationBlock,
            inputs.kmsRegistrationBlockHash,
            inputs.targetBootInfo,
            inputs.restartKeyDerivationProofHash
        );
        vm.stopBroadcast();

        require(
            auth.pendingKmsContract() == inputs.kmsContract
                && auth.pendingKmsRuntimeCodeHash() == inputs.kmsRuntimeCodeHash
                && auth.pendingKmsImplementation() == inputs.kmsImplementation
                && auth.pendingKmsImplementationRuntimeCodeHash() == inputs.kmsImplementationRuntimeCodeHash
                && auth.pendingKmsRegistrationTxHash() == inputs.kmsRegistrationTxHash
                && auth.pendingKmsRegistrationBlock() == inputs.kmsRegistrationBlock
                && auth.pendingKmsRegistrationBlockHash() == inputs.kmsRegistrationBlockHash
                && auth.pendingRestartKeyDerivationProofHash() == inputs.restartKeyDerivationProofHash
                && auth.pendingKmsBindingActivatesAt() > block.timestamp,
            "phase 3 did not stage the exact KMS and external evidence binding"
        );
    }

    function _phaseFour(ReleaseInputs memory inputs) internal {
        EmailOracleAuth auth = inputs.auth;
        _requireExactPhaseTwoState(inputs);
        _requireKmsEvidenceInputs(inputs);
        require(
            auth.pendingKmsContract() == inputs.kmsContract
                && auth.pendingKmsRuntimeCodeHash() == inputs.kmsRuntimeCodeHash
                && auth.pendingKmsImplementation() == inputs.kmsImplementation
                && auth.pendingKmsImplementationRuntimeCodeHash() == inputs.kmsImplementationRuntimeCodeHash
                && auth.pendingKmsRegistrationTxHash() == inputs.kmsRegistrationTxHash
                && auth.pendingKmsRegistrationBlock() == inputs.kmsRegistrationBlock
                && auth.pendingKmsRegistrationBlockHash() == inputs.kmsRegistrationBlockHash
                && auth.pendingRestartKeyDerivationProofHash() == inputs.restartKeyDerivationProofHash,
            "phase 4 KMS evidence does not match the staged binding"
        );
        uint256 activatesAt = auth.pendingKmsBindingActivatesAt();
        require(activatesAt != 0 && activatesAt <= block.timestamp, "KMS binding timelock has not elapsed");

        vm.startBroadcast();
        auth.activateAndFreezeKmsBinding(inputs.targetBootInfo);
        auth.freezeConsumerManagerAdditions(inputs.consumerAppId);
        auth.freezeConsumerRegistry(inputs.consumerAppId, inputs.consumerComposeHash);
        vm.stopBroadcast();

        require(auth.releaseConfigurationReady(), "phase 4 did not close an exact ready email release");
        require(
            auth.kmsContract() == inputs.kmsContract && auth.kmsRuntimeCodeHash() == inputs.kmsRuntimeCodeHash
                && auth.kmsImplementation() == inputs.kmsImplementation
                && auth.kmsImplementationRuntimeCodeHash() == inputs.kmsImplementationRuntimeCodeHash
                && auth.kmsRegistrationTxHash() == inputs.kmsRegistrationTxHash
                && auth.kmsRegistrationBlock() == inputs.kmsRegistrationBlock
                && auth.kmsRegistrationBlockHash() == inputs.kmsRegistrationBlockHash
                && auth.restartKeyDerivationProofHash() == inputs.restartKeyDerivationProofHash,
            "phase 4 active KMS binding mismatch"
        );
    }

    function _requireExactPhaseTwoState(ReleaseInputs memory inputs) internal view {
        EmailOracleAuth auth = inputs.auth;
        require(
            auth.oracleCodeFrozen() && !auth.consumerRegistryFrozen() && !auth.consumerManagerAdditionsFrozen()
                && !auth.kmsBindingFrozen() && auth.allowedOracleComposeHashCount() == 1
                && auth.pendingOracleComposeHashCount() == 0 && auth.allowedDeviceIdCount() == 1
                && auth.consumerManagerCount() == 1 && auth.totalConsumerComposeHashCount() == 1
                && auth.allowedOracleComposeHashes(inputs.oracleComposeHash) && auth.allowedDeviceIds(inputs.deviceId)
                && auth.consumerManagers(inputs.consumerAppId)
                && auth.consumerComposeHashCount(inputs.consumerAppId) == 1
                && auth.isConsumerComposeHashRegistered(inputs.consumerAppId, inputs.consumerComposeHash)
                && !auth.isConsumerAuthorized(inputs.consumerAppId, inputs.consumerComposeHash)
                && auth.releaseOracleComposeHash() == inputs.oracleComposeHash
                && auth.releaseDeviceId() == inputs.deviceId,
            "KMS phases require the exact frozen oracle and mutable consumer policy"
        );
    }

    function _requireKmsEvidenceInputs(ReleaseInputs memory inputs) internal view {
        require(
            inputs.kmsContract != address(0) && inputs.kmsContract != address(inputs.auth)
                && inputs.kmsContract != inputs.operator && inputs.kmsImplementation != address(0)
                && inputs.kmsImplementation != address(inputs.auth) && inputs.kmsImplementation != inputs.operator
                && inputs.kmsImplementation != inputs.kmsContract,
            "KMS contracts conflict with release roles"
        );
        require(
            inputs.kmsRuntimeCodeHash != bytes32(0) && inputs.kmsContract.codehash == inputs.kmsRuntimeCodeHash
                && inputs.kmsImplementationRuntimeCodeHash != bytes32(0)
                && inputs.kmsImplementation.codehash == inputs.kmsImplementationRuntimeCodeHash,
            "KMS runtime code hash mismatch"
        );
        require(
            inputs.kmsRegistrationTxHash != bytes32(0) && inputs.kmsRegistrationBlock != 0
                && inputs.kmsRegistrationBlock < block.number && inputs.kmsRegistrationBlockHash != bytes32(0)
                && inputs.restartKeyDerivationProofHash != bytes32(0),
            "KMS registration and restart evidence must be nonzero"
        );
        require(
            inputs.targetBootInfo.appId == address(inputs.auth)
                && inputs.targetBootInfo.composeHash == inputs.oracleComposeHash
                && inputs.targetBootInfo.deviceId == inputs.deviceId && inputs.targetBootInfo.instanceId != address(0)
                && inputs.targetBootInfo.mrAggregated != bytes32(0) && inputs.targetBootInfo.mrSystem != bytes32(0)
                && inputs.targetBootInfo.osImageHash != bytes32(0)
                && keccak256(bytes(inputs.targetBootInfo.tcbStatus)) == keccak256(bytes("UpToDate"))
                && inputs.targetBootInfo.advisoryIds.length == 0,
            "target boot tuple does not match the exact release"
        );
    }
}
