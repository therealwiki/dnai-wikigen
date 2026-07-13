// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

contract TinkerAccountEncumbranceScript is Script {
    function run() public {
        address owner = vm.envOr("TINKER_ENCUMBRANCE_OWNER", msg.sender);
        bytes32 accountCommitment = vm.envBytes32("TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT");
        bytes32 initialComposeHash = vm.envBytes32("TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH");
        uint256 maxAddBalanceWei = vm.envUint("TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI");
        uint256 maxSpendWei = vm.envUint("TINKER_ENCUMBRANCE_MAX_SPEND_WEI");
        bool freezeMeasurements = vm.envOr("TINKER_ENCUMBRANCE_FREEZE_MEASUREMENTS", false);

        vm.startBroadcast();

        TinkerAccountEncumbrance encumbrance = new TinkerAccountEncumbrance(
            owner,
            accountCommitment,
            initialComposeHash,
            maxAddBalanceWei,
            maxSpendWei
        );

        if (freezeMeasurements) {
            encumbrance.freezeMeasurements();
        }

        vm.stopBroadcast();

        console.log("TinkerAccountEncumbrance deployed at:", address(encumbrance));
        console.log("Owner:", encumbrance.owner());
        console.logBytes32(encumbrance.accountCommitment());
        console.logBytes32(initialComposeHash);
        console.log("Max add balance policy units:", encumbrance.maxAddBalanceWei());
        console.log("Max spend policy units:", encumbrance.maxSpendWei());
        console.log("Measurements frozen:", encumbrance.measurementsFrozen());
    }
}
