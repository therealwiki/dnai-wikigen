// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {DiligenceRoom} from "../src/DiligenceRoom.sol";

contract DiligenceRoomScript is Script {
    function run() public {
        address resultVerifier = vm.envOr("DILIGENCE_RESULT_VERIFIER", msg.sender);

        vm.startBroadcast();

        DiligenceRoom room = new DiligenceRoom(resultVerifier);
        console.log("DiligenceRoom deployed at:", address(room));
        console.log("Developer (fee recipient):", room.developer());
        console.log("Result verifier:", room.resultVerifier());

        vm.stopBroadcast();
    }
}
