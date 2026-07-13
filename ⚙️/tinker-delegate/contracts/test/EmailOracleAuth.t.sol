// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {EmailOracleAuth} from "../src/EmailOracleAuth.sol";
import {IAppAuth} from "../src/interfaces/IAppAuth.sol";

contract EmailOracleAuthTest is Test {
    EmailOracleAuth internal auth;

    address internal owner = makeAddr("owner");
    address internal other = makeAddr("other");
    address internal manager = makeAddr("manager");
    address internal consumer = makeAddr("consumer");

    bytes32 internal initialComposeHash = keccak256("oracle-compose-v1");
    bytes32 internal nextComposeHash = keccak256("oracle-compose-v2");
    bytes32 internal deviceId = keccak256("device-1");
    bytes32 internal consumerComposeHash = keccak256("delegate-compose-v1");

    function setUp() public {
        auth = new EmailOracleAuth(owner, 2 days, true, bytes32(0), initialComposeHash);
    }

    function _bootInfo(
        address appId,
        bytes32 composeHash,
        bytes32 bootDeviceId
    ) internal pure returns (IAppAuth.AppBootInfo memory info) {
        info = IAppAuth.AppBootInfo({
            appId: appId,
            composeHash: composeHash,
            instanceId: address(0x1234),
            deviceId: bootDeviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });
    }

    function test_InitialComposeHashIsAllowed() public {
        (bool allowed, string memory reason) = auth.isAppAllowed(
            _bootInfo(address(auth), initialComposeHash, bytes32(0))
        );

        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_IsAppAllowed_RejectsWrongAppId() public {
        (bool allowed, string memory reason) = auth.isAppAllowed(
            _bootInfo(address(0xBEEF), initialComposeHash, bytes32(0))
        );

        assertFalse(allowed);
        assertEq(reason, "App ID mismatch");
    }

    function test_ProposeAndActivateOracleComposeHash() public {
        vm.prank(owner);
        auth.proposeOracleComposeHash(nextComposeHash);

        vm.warp(block.timestamp + 2 days);
        auth.activateOracleComposeHash(nextComposeHash);

        (bool allowed, string memory reason) = auth.isAppAllowed(
            _bootInfo(address(auth), nextComposeHash, bytes32(0))
        );
        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_ActivateOracleComposeHash_RevertTooEarly() public {
        vm.prank(owner);
        auth.proposeOracleComposeHash(nextComposeHash);

        vm.expectRevert(
            abi.encodeWithSelector(EmailOracleAuth.ActivationTooEarly.selector, block.timestamp + 2 days)
        );
        auth.activateOracleComposeHash(nextComposeHash);
    }

    function test_DeviceRestriction() public {
        vm.startPrank(owner);
        auth.setAllowAnyDevice(false);
        auth.addDevice(deviceId);
        vm.stopPrank();

        (bool allowedWrongDevice, ) = auth.isAppAllowed(
            _bootInfo(address(auth), initialComposeHash, keccak256("other-device"))
        );
        assertFalse(allowedWrongDevice);

        (bool allowedRightDevice, ) = auth.isAppAllowed(
            _bootInfo(address(auth), initialComposeHash, deviceId)
        );
        assertTrue(allowedRightDevice);
    }

    function test_OwnerCanDelegateConsumerManagement() public {
        vm.prank(owner);
        auth.setConsumerManager(manager, true);

        vm.prank(manager);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);

        assertTrue(auth.isConsumerAuthorized(consumer, consumerComposeHash));
        assertEq(auth.consumerComposeHashCount(consumer), 1);
    }

    function test_ManagerCannotChangeOraclePolicy() public {
        vm.prank(owner);
        auth.setConsumerManager(manager, true);

        vm.prank(manager);
        vm.expectRevert(EmailOracleAuth.NotOwner.selector);
        auth.proposeOracleComposeHash(nextComposeHash);
    }

    function test_FreezeOracleCodeAuth_StillAllowsConsumerUpdates() public {
        vm.prank(owner);
        auth.freezeOracleCodeAuth();

        vm.prank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);

        assertTrue(auth.oracleCodeFrozen());
        assertTrue(auth.isConsumerAuthorized(consumer, consumerComposeHash));

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.OracleCodeFrozen.selector);
        auth.proposeOracleComposeHash(nextComposeHash);
    }

    function test_FreezeConsumerRegistry_BlocksOwnerAndManager() public {
        vm.startPrank(owner);
        auth.setConsumerManager(manager, true);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.freezeConsumerRegistry();
        vm.stopPrank();

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.ConsumerRegistryFrozen.selector);
        auth.removeConsumerComposeHash(consumer, consumerComposeHash);

        vm.prank(manager);
        vm.expectRevert(EmailOracleAuth.ConsumerRegistryFrozen.selector);
        auth.addConsumerComposeHash(consumer, keccak256("delegate-compose-v2"));
    }

    function test_RemoveConsumerComposeHashRevokesAuthorization() public {
        vm.startPrank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.removeConsumerComposeHash(consumer, consumerComposeHash);
        vm.stopPrank();

        assertFalse(auth.isConsumerAuthorized(consumer, consumerComposeHash));
        assertEq(auth.consumerComposeHashCount(consumer), 0);
    }

    function test_FreezeOracleCodeAuth_BlocksDeviceMutations() public {
        vm.prank(owner);
        auth.freezeOracleCodeAuth();

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.OracleCodeFrozen.selector);
        auth.addDevice(deviceId);
    }

    // ── Oracle compose-hash proposal lifecycle ─────────────────────────

    function test_CancelOracleComposeHashProposal_BlocksActivation() public {
        vm.startPrank(owner);
        auth.proposeOracleComposeHash(nextComposeHash);
        auth.cancelOracleComposeHashProposal(nextComposeHash);
        vm.stopPrank();

        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(EmailOracleAuth.NotPending.selector);
        auth.activateOracleComposeHash(nextComposeHash);

        (bool allowed, ) = auth.isAppAllowed(_bootInfo(address(auth), nextComposeHash, bytes32(0)));
        assertFalse(allowed);
    }

    function test_CancelOracleComposeHashProposal_RevertNotPending() public {
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.NotPending.selector);
        auth.cancelOracleComposeHashProposal(nextComposeHash);
    }

    function test_ProposeOracleComposeHash_RevertAlreadyPending() public {
        vm.startPrank(owner);
        auth.proposeOracleComposeHash(nextComposeHash);
        vm.expectRevert(EmailOracleAuth.AlreadyPending.selector);
        auth.proposeOracleComposeHash(nextComposeHash);
        vm.stopPrank();
    }

    function test_ProposeOracleComposeHash_RevertAlreadyAllowed() public {
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.AlreadyAllowed.selector);
        auth.proposeOracleComposeHash(initialComposeHash);
    }

    function test_ProposeOracleComposeHash_RevertZeroHash() public {
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.ZeroHash.selector);
        auth.proposeOracleComposeHash(bytes32(0));
    }

    function test_ActivateOracleComposeHash_RevertNotPending() public {
        vm.expectRevert(EmailOracleAuth.NotPending.selector);
        auth.activateOracleComposeHash(nextComposeHash);
    }

    function test_RemoveOracleComposeHash_RevokesAuthorization() public {
        vm.startPrank(owner);
        auth.proposeOracleComposeHash(nextComposeHash);
        vm.warp(block.timestamp + 2 days);
        auth.activateOracleComposeHash(nextComposeHash);
        auth.removeOracleComposeHash(nextComposeHash);
        vm.stopPrank();

        (bool allowed, ) = auth.isAppAllowed(_bootInfo(address(auth), nextComposeHash, bytes32(0)));
        assertFalse(allowed);
    }

    function test_RemoveOracleComposeHash_RevertNotAllowed() public {
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.NotAllowed.selector);
        auth.removeOracleComposeHash(nextComposeHash);
    }

    // ── Device toggle ──────────────────────────────────────────────────

    function test_SetAllowAnyDevice_ToggleReenablesAnyDevice() public {
        vm.startPrank(owner);
        auth.setAllowAnyDevice(false);
        auth.addDevice(deviceId);
        vm.stopPrank();

        (bool blocked, ) = auth.isAppAllowed(
            _bootInfo(address(auth), initialComposeHash, keccak256("unknown-device"))
        );
        assertFalse(blocked);

        vm.prank(owner);
        auth.setAllowAnyDevice(true);
        (bool nowAllowed, ) = auth.isAppAllowed(
            _bootInfo(address(auth), initialComposeHash, keccak256("unknown-device"))
        );
        assertTrue(nowAllowed);
    }

    function test_AddDevice_RevertAlreadyAllowed() public {
        vm.startPrank(owner);
        auth.addDevice(deviceId);
        vm.expectRevert(EmailOracleAuth.AlreadyAllowed.selector);
        auth.addDevice(deviceId);
        vm.stopPrank();
    }

    function test_RemoveDevice_RevertNotAllowed() public {
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.NotAllowed.selector);
        auth.removeDevice(deviceId);
    }

    // ── Ownership ──────────────────────────────────────────────────────

    function test_TransferOwnership_MovesControl() public {
        vm.prank(owner);
        auth.transferOwnership(other);
        assertEq(auth.owner(), other);

        // Old owner can no longer mutate policy.
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.NotOwner.selector);
        auth.setAllowAnyDevice(false);

        // New owner can.
        vm.prank(other);
        auth.setAllowAnyDevice(false);
        assertFalse(auth.allowAnyDevice());
    }

    function test_TransferOwnership_RevertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.ZeroAddress.selector);
        auth.transferOwnership(address(0));
    }

    // ── Access control ─────────────────────────────────────────────────

    function test_NonOwnerCannotProposeOracleComposeHash() public {
        vm.prank(other);
        vm.expectRevert(EmailOracleAuth.NotOwner.selector);
        auth.proposeOracleComposeHash(nextComposeHash);
    }

    function test_NonOwnerCannotSetConsumerManager() public {
        vm.prank(other);
        vm.expectRevert(EmailOracleAuth.NotOwner.selector);
        auth.setConsumerManager(manager, true);
    }

    function test_ManagerCannotAddDevice() public {
        vm.prank(owner);
        auth.setConsumerManager(manager, true);

        vm.prank(manager);
        vm.expectRevert(EmailOracleAuth.NotOwner.selector);
        auth.addDevice(deviceId);
    }

    function test_NonManagerCannotAddConsumerComposeHash() public {
        vm.prank(other);
        vm.expectRevert(EmailOracleAuth.NotOwnerOrConsumerManager.selector);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
    }

    // ── Emergency consumer revocation (kill switch) ─────────────────────

    function test_EmergencyRevokeConsumer_RevokesAllComposeHashesImmediately() public {
        bytes32 secondHash = keccak256("delegate-compose-v2");
        vm.startPrank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.addConsumerComposeHash(consumer, secondHash);
        vm.stopPrank();
        assertTrue(auth.isConsumerAuthorized(consumer, consumerComposeHash));
        assertTrue(auth.isConsumerAuthorized(consumer, secondHash));

        vm.prank(owner);
        auth.emergencyRevokeConsumer(consumer);

        // Every compose hash for the consumer is unauthorized at once.
        assertTrue(auth.consumerEmergencyRevoked(consumer));
        assertFalse(auth.isConsumerAuthorized(consumer, consumerComposeHash));
        assertFalse(auth.isConsumerAuthorized(consumer, secondHash));
    }

    function test_EmergencyRevokeConsumer_WorksEvenWhenRegistryFrozen() public {
        vm.startPrank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.freezeConsumerRegistry();
        // Per-hash removal is blocked once frozen...
        vm.expectRevert(EmailOracleAuth.ConsumerRegistryFrozen.selector);
        auth.removeConsumerComposeHash(consumer, consumerComposeHash);
        // ...but the emergency kill switch still works.
        auth.emergencyRevokeConsumer(consumer);
        vm.stopPrank();

        assertFalse(auth.isConsumerAuthorized(consumer, consumerComposeHash));
    }

    function test_EmergencyRevokeConsumer_ManagerCanTrigger() public {
        vm.startPrank(owner);
        auth.setConsumerManager(manager, true);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        vm.stopPrank();

        vm.prank(manager);
        auth.emergencyRevokeConsumer(consumer);
        assertFalse(auth.isConsumerAuthorized(consumer, consumerComposeHash));
    }

    function test_EmergencyRevokeConsumer_RejectsNonManager() public {
        vm.prank(other);
        vm.expectRevert(EmailOracleAuth.NotOwnerOrConsumerManager.selector);
        auth.emergencyRevokeConsumer(consumer);
    }

    function test_EmergencyRevokeConsumer_RejectsZeroAndDouble() public {
        vm.startPrank(owner);
        vm.expectRevert(EmailOracleAuth.ZeroAddress.selector);
        auth.emergencyRevokeConsumer(address(0));

        auth.emergencyRevokeConsumer(consumer);
        vm.expectRevert(EmailOracleAuth.AlreadyAllowed.selector);
        auth.emergencyRevokeConsumer(consumer);
        vm.stopPrank();
    }

    function test_RestoreConsumer_ReenablesBeforeFreezeOnly() public {
        vm.startPrank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.emergencyRevokeConsumer(consumer);
        assertFalse(auth.isConsumerAuthorized(consumer, consumerComposeHash));
        // Owner can recover from a false alarm while the registry is mutable.
        auth.restoreConsumer(consumer);
        vm.stopPrank();
        assertTrue(auth.isConsumerAuthorized(consumer, consumerComposeHash));
    }

    function test_RestoreConsumer_BlockedAfterFreeze() public {
        vm.startPrank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.emergencyRevokeConsumer(consumer);
        auth.freezeConsumerRegistry();
        // Once frozen, an emergency kill is permanent.
        vm.expectRevert(EmailOracleAuth.ConsumerRegistryFrozen.selector);
        auth.restoreConsumer(consumer);
        vm.stopPrank();
        assertFalse(auth.isConsumerAuthorized(consumer, consumerComposeHash));
    }

    function test_RestoreConsumer_RejectsNonOwnerAndNotRevoked() public {
        vm.prank(owner);
        auth.setConsumerManager(manager, true);
        // Manager cannot restore (re-enabling is owner-only).
        vm.prank(manager);
        vm.expectRevert(EmailOracleAuth.NotOwner.selector);
        auth.restoreConsumer(consumer);
        // Restoring a consumer that was never revoked reverts.
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.NotAllowed.selector);
        auth.restoreConsumer(consumer);
    }

    // ── Hashed OTP-delivery audit records ───────────────────────────────

    function test_RecordOtpDelivery_EmitsOrderedSequence() public {
        bytes32 deliveryHash = keccak256("consumer:req-1:otp-hash");
        vm.startPrank(owner);

        vm.expectEmit(true, true, true, true);
        emit EmailOracleAuth.OtpDeliveryRecorded(consumer, deliveryHash, 1, block.timestamp);
        uint256 seq1 = auth.recordOtpDelivery(consumer, deliveryHash);

        uint256 seq2 = auth.recordOtpDelivery(consumer, keccak256("consumer:req-2:otp-hash"));
        vm.stopPrank();

        assertEq(seq1, 1);
        assertEq(seq2, 2);
        assertEq(auth.otpDeliveryCount(consumer), 2);
    }

    function test_RecordOtpDelivery_ManagerCanRecord() public {
        vm.prank(owner);
        auth.setConsumerManager(manager, true);
        vm.prank(manager);
        uint256 seq = auth.recordOtpDelivery(consumer, keccak256("d"));
        assertEq(seq, 1);
    }

    function test_RecordOtpDelivery_RejectsNonManager() public {
        vm.prank(other);
        vm.expectRevert(EmailOracleAuth.NotOwnerOrConsumerManager.selector);
        auth.recordOtpDelivery(consumer, keccak256("d"));
    }

    function test_RecordOtpDelivery_RejectsZeroInputs() public {
        vm.startPrank(owner);
        vm.expectRevert(EmailOracleAuth.ZeroAddress.selector);
        auth.recordOtpDelivery(address(0), keccak256("d"));
        vm.expectRevert(EmailOracleAuth.ZeroHash.selector);
        auth.recordOtpDelivery(consumer, bytes32(0));
        vm.stopPrank();
    }

    function test_RecordOtpDelivery_FailsClosedForRevokedConsumer() public {
        vm.startPrank(owner);
        auth.emergencyRevokeConsumer(consumer);
        vm.expectRevert(EmailOracleAuth.NotAllowed.selector);
        auth.recordOtpDelivery(consumer, keccak256("d"));
        vm.stopPrank();
    }
}
