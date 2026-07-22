// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {TinkerAccountEncumbrance} from "../src/TinkerAccountEncumbrance.sol";

contract TinkerAccountEncumbranceScript is Script {
    function run() public {
        require(
            block.chainid != 84532 && block.chainid != 8453,
            "use DeployFreshSuite for Base TinkerAccountEncumbrance releases"
        );

        address owner = vm.envAddress("TINKER_ENCUMBRANCE_OWNER");
        bytes32 accountCommitment = vm.envBytes32("TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT");
        bytes32 initialComposeHash = vm.envOr("TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH", bytes32(0));
        uint256 maxAddBalanceWei = vm.envUint("TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI");
        uint256 maxSpendWei = vm.envUint("TINKER_ENCUMBRANCE_MAX_SPEND_WEI");
        vm.startBroadcast();

        TinkerAccountEncumbrance encumbrance =
            new TinkerAccountEncumbrance(owner, accountCommitment, initialComposeHash, maxAddBalanceWei, maxSpendWei);

        vm.stopBroadcast();

        console.log("TinkerAccountEncumbrance deployed at:", address(encumbrance));
        console.log("Owner:", encumbrance.owner());
        console.logBytes32(encumbrance.accountCommitment());
        console.logBytes32(initialComposeHash);
        console.log("Max add balance policy units:", encumbrance.maxAddBalanceWei());
        console.log("Max spend policy units:", encumbrance.maxSpendWei());
        console.log("Emergency halted:", encumbrance.emergencyHalted());
        console.log("Release policy frozen:", encumbrance.releasePolicyFrozen());
        console.logBytes32(encumbrance.approvedComposeRoot());
        console.log("Approved compose count:", encumbrance.approvedComposeCount());
        console.logBytes32(encumbrance.managerRoot());
        console.log("Manager count:", encumbrance.managerCount());
    }
}
