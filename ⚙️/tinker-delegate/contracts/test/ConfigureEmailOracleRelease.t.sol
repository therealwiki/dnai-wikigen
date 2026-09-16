// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ConfigureEmailOracleReleaseScript} from "../script/ConfigureEmailOracleRelease.s.sol";
import {EmailOracleAuth} from "../src/EmailOracleAuth.sol";
import {IAppAuth} from "../src/interfaces/IAppAuth.sol";

contract ConfigureEmailKmsImplementation {}

contract ConfigureEmailKms {
    mapping(address => bool) public registeredApps;
    bool public bootAllowed = true;

    function setRegistered(address appId, bool allowed) external {
        registeredApps[appId] = allowed;
    }

    function setBootAllowed(bool allowed) external {
        bootAllowed = allowed;
    }

    function isAppAllowed(IAppAuth.AppBootInfo calldata) external view returns (bool isAllowed, string memory reason) {
        return bootAllowed ? (true, "") : (false, "denied");
    }
}

contract ConfigureEmailOracleReleaseHarness is ConfigureEmailOracleReleaseScript {
    function executeConfiguredPhase(uint256 phase, ReleaseInputs memory inputs) external {
        _executePhase(phase, inputs);
    }
}

contract ConfigureEmailOracleReleaseTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    ConfigureEmailOracleReleaseHarness internal script;
    EmailOracleAuth internal auth;
    ConfigureEmailKms internal kms;
    ConfigureEmailKmsImplementation internal kmsImplementation;
    address internal operator;
    address internal tee = makeAddr("email-main-cvm-tee");
    bytes32 internal oracleCompose = keccak256("email-oracle-release-compose");
    bytes32 internal consumerCompose = keccak256("main-runtime-consumer-compose");
    bytes32 internal deviceId = keccak256("phala-device");

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        auth = new EmailOracleAuth(operator, 2 days, false, bytes32(0), bytes32(0), true);
        kms = new ConfigureEmailKms();
        kmsImplementation = new ConfigureEmailKmsImplementation();
        script = new ConfigureEmailOracleReleaseHarness();
        vm.roll(100);
    }

    function test_FourPhasesProduceExactClosedKmsBoundRelease() public {
        _runPhase(1);
        assertEq(auth.pendingOracleComposeHashCount(), 1);
        assertEq(auth.allowedDeviceIdCount(), 1);
        assertEq(auth.consumerManagerCount(), 1);
        assertEq(auth.totalConsumerComposeHashCount(), 1);
        assertTrue(auth.isConsumerComposeHashRegistered(tee, consumerCompose));
        assertFalse(auth.isConsumerAuthorized(tee, consumerCompose));

        vm.warp(auth.pendingOracleComposeHashes(oracleCompose));
        _runPhase(2);
        assertTrue(auth.oracleCodeFrozen());
        assertFalse(auth.kmsBindingFrozen());
        assertFalse(auth.isConsumerAuthorized(tee, consumerCompose));

        kms.setRegistered(address(auth), true);
        _runPhase(3);
        assertGt(auth.pendingKmsBindingActivatesAt(), block.timestamp);
        assertEq(auth.pendingKmsRegistrationTxHash(), keccak256("kms-registration-tx"));
        assertFalse(auth.isConsumerAuthorized(tee, consumerCompose));

        vm.warp(auth.pendingKmsBindingActivatesAt());
        _runPhase(4);
        assertTrue(auth.kmsBindingFrozen());
        assertTrue(auth.consumerManagerAdditionsFrozen());
        assertTrue(auth.consumerRegistryFrozen());
        assertTrue(auth.releaseConfigurationReady());
        assertTrue(auth.isConsumerAuthorized(tee, consumerCompose));
    }

    function test_CannotSkipTimelocksOrReplayPhases() public {
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 policy"));
        _runPhase(2);
        _runPhase(1);
        vm.expectRevert(bytes("phase 1 requires the exact fresh deny-all EmailOracleAuth"));
        _runPhase(1);
        vm.expectRevert(bytes("oracle compose timelock has not elapsed"));
        _runPhase(2);
    }

    function test_ExtraConsumerPolicyBlocksReleaseClosure() public {
        _runPhase(1);
        vm.prank(tee);
        auth.addConsumerComposeHash(makeAddr("extra-consumer"), keccak256("extra-consumer-compose"));
        vm.warp(auth.pendingOracleComposeHashes(oracleCompose));
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 policy"));
        _runPhase(2);
        assertFalse(auth.oracleCodeFrozen());
    }

    function test_PhaseThreeRequiresRegisteredExactKmsRuntimeAndPhaseFourRechecksBoot() public {
        _runPhase(1);
        vm.warp(auth.pendingOracleComposeHashes(oracleCompose));
        _runPhase(2);

        vm.expectRevert(EmailOracleAuth.KmsRegistrationMissing.selector);
        _runPhase(3);
        vm.stopBroadcast();

        kms.setRegistered(address(auth), true);
        ConfigureEmailOracleReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.kmsRuntimeCodeHash = keccak256("wrong-runtime");
        vm.expectRevert(bytes("KMS runtime code hash mismatch"));
        script.executeConfiguredPhase(3, inputs);

        kms.setBootAllowed(false);
        _runPhase(3);
        uint256 activatesAt = auth.pendingKmsBindingActivatesAt();
        assertGt(activatesAt, block.timestamp);
        assertEq(auth.pendingKmsContract(), address(kms));
        assertEq(auth.pendingKmsRuntimeCodeHash(), address(kms).codehash);
        assertFalse(auth.kmsBindingFrozen());
        assertFalse(auth.consumerManagerAdditionsFrozen());
        assertFalse(auth.consumerRegistryFrozen());
        assertFalse(auth.releaseConfigurationReady());

        vm.warp(activatesAt);
        vm.expectRevert(EmailOracleAuth.KmsBootAuthorizationDenied.selector);
        _runPhase(4);
        vm.stopBroadcast();

        assertEq(auth.pendingKmsBindingActivatesAt(), activatesAt);
        assertEq(auth.pendingKmsContract(), address(kms));
        assertEq(auth.pendingKmsRuntimeCodeHash(), address(kms).codehash);
        assertEq(auth.pendingKmsRegistrationTxHash(), keccak256("kms-registration-tx"));
        assertFalse(auth.kmsBindingFrozen());
        assertFalse(auth.consumerManagerAdditionsFrozen());
        assertFalse(auth.consumerRegistryFrozen());
        assertFalse(auth.releaseConfigurationReady());
        assertFalse(auth.isConsumerAuthorized(tee, consumerCompose));
    }

    function test_PhaseFourRechecksKmsRegistrationAfterDelay() public {
        _runPhase(1);
        vm.warp(auth.pendingOracleComposeHashes(oracleCompose));
        _runPhase(2);
        kms.setRegistered(address(auth), true);
        _runPhase(3);
        vm.warp(auth.pendingKmsBindingActivatesAt());
        kms.setRegistered(address(auth), false);

        vm.expectRevert(EmailOracleAuth.KmsRegistrationMissing.selector);
        _runPhase(4);
        assertFalse(auth.kmsBindingFrozen());
        assertFalse(auth.consumerRegistryFrozen());
    }

    function test_RuntimeOperatorAndTargetRolePinsAreRequired() public {
        ConfigureEmailOracleReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.authRuntimeCodeHash = keccak256("wrong-runtime");
        vm.expectRevert(bytes("EmailOracleAuth runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.operator = makeAddr("wrong-operator");
        vm.expectRevert(bytes("operator does not own EmailOracleAuth"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.consumerAppId = operator;
        vm.expectRevert(bytes("consumer app conflicts with a control role"));
        script.executeConfiguredPhase(1, inputs);
    }

    function _runPhase(uint256 phase) internal {
        script.executeConfiguredPhase(phase, _inputs());
    }

    function _inputs() internal view returns (ConfigureEmailOracleReleaseScript.ReleaseInputs memory inputs) {
        string[] memory advisoryIds = new string[](0);
        inputs = ConfigureEmailOracleReleaseScript.ReleaseInputs({
            auth: auth,
            authRuntimeCodeHash: address(auth).codehash,
            operator: operator,
            oracleComposeHash: oracleCompose,
            deviceId: deviceId,
            consumerAppId: tee,
            consumerComposeHash: consumerCompose,
            kmsContract: address(kms),
            kmsRuntimeCodeHash: address(kms).codehash,
            kmsImplementation: address(kmsImplementation),
            kmsImplementationRuntimeCodeHash: address(kmsImplementation).codehash,
            kmsRegistrationTxHash: keccak256("kms-registration-tx"),
            kmsRegistrationBlock: 99,
            kmsRegistrationBlockHash: keccak256("kms-registration-block"),
            targetBootInfo: IAppAuth.AppBootInfo({
                appId: address(auth),
                composeHash: oracleCompose,
                instanceId: address(0x1234),
                deviceId: deviceId,
                mrAggregated: keccak256("mr-aggregated"),
                mrSystem: keccak256("mr-system"),
                osImageHash: keccak256("os-image"),
                tcbStatus: "UpToDate",
                advisoryIds: advisoryIds
            }),
            restartKeyDerivationProofHash: keccak256("qvl-verified-restart-key-proof")
        });
    }
}
