// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {EmailOracleAuth} from "../src/EmailOracleAuth.sol";

interface IDstackKmsLike {
    function registerApp(address appId) external;
}

contract EmailOracleAuthScript is Script {
    function run() public {
        address owner = vm.envOr("EMAIL_ORACLE_OWNER", msg.sender);
        uint256 upgradeDelay = vm.envOr("EMAIL_ORACLE_UPGRADE_DELAY", uint256(2 days));
        bool allowAnyDevice = vm.envOr("EMAIL_ORACLE_ALLOW_ANY_DEVICE", true);
        bytes32 initialDeviceId = vm.envOr("EMAIL_ORACLE_INITIAL_DEVICE_ID", bytes32(0));
        bytes32 initialComposeHash = vm.envOr("EMAIL_ORACLE_INITIAL_COMPOSE_HASH", bytes32(0));

        address initialConsumerManager = vm.envOr("EMAIL_ORACLE_CONSUMER_MANAGER", address(0));
        address initialConsumerApp = vm.envOr("EMAIL_ORACLE_INITIAL_CONSUMER_APP", address(0));
        bytes32 initialConsumerComposeHash = vm.envOr("EMAIL_ORACLE_INITIAL_CONSUMER_HASH", bytes32(0));

        bool freezeOracle = vm.envOr("EMAIL_ORACLE_FREEZE_ORACLE", false);
        bool freezeConsumers = vm.envOr("EMAIL_ORACLE_FREEZE_CONSUMERS", false);

        address kmsAddress = vm.envOr("EMAIL_ORACLE_KMS_ADDRESS", address(0));
        bool registerWithKms = vm.envOr("EMAIL_ORACLE_REGISTER_WITH_KMS", false);

        vm.startBroadcast();

        EmailOracleAuth auth = new EmailOracleAuth(
            owner,
            upgradeDelay,
            allowAnyDevice,
            initialDeviceId,
            initialComposeHash
        );

        if (initialConsumerManager != address(0)) {
            auth.setConsumerManager(initialConsumerManager, true);
        }

        if (initialConsumerApp != address(0) && initialConsumerComposeHash != bytes32(0)) {
            auth.addConsumerComposeHash(initialConsumerApp, initialConsumerComposeHash);
        }

        if (registerWithKms) {
            require(kmsAddress != address(0), "EMAIL_ORACLE_KMS_ADDRESS required");
            IDstackKmsLike(kmsAddress).registerApp(address(auth));
        }

        if (freezeOracle) {
            auth.freezeOracleCodeAuth();
        }

        if (freezeConsumers) {
            auth.freezeConsumerRegistry();
        }

        vm.stopBroadcast();

        console.log("EmailOracleAuth deployed at:", address(auth));
        console.log("Owner:", auth.owner());
        console.log("Oracle upgrade delay:", auth.ORACLE_UPGRADE_DELAY());
        console.log("Allow any device:", auth.allowAnyDevice());
        console.log("Oracle code frozen:", auth.oracleCodeFrozen());
        console.log("Consumer registry frozen:", auth.consumerRegistryFrozen());
        console.log("Registered with KMS:", registerWithKms);
    }
}
