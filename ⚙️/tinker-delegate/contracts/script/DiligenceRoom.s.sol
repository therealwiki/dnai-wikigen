// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {DiligenceRoom} from "../src/DiligenceRoom.sol";

contract DiligenceRoomScript is Script {
    function run() public {
        require(block.chainid != 84532 && block.chainid != 8453, "use DeployFreshSuite for Base DiligenceRoom releases");

        address operator = vm.envAddress("DEPLOYMENT_OPERATOR");
        require(operator != address(0), "DEPLOYMENT_OPERATOR must be nonzero");

        vm.startBroadcast();

        DiligenceRoom room = new DiligenceRoom(false);
        require(room.developer() == operator, "broadcast signer does not match DEPLOYMENT_OPERATOR");
        console.log("DiligenceRoom deployed at:", address(room));
        console.log("Developer (fee recipient):", room.developer());
        console.log("Result verifier (post-deploy):", room.resultVerifier());

        vm.stopBroadcast();
    }
}
