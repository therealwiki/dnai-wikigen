// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {EmailOracleAuth} from "../src/EmailOracleAuth.sol";
import {IAppAuth} from "../src/interfaces/IAppAuth.sol";

contract MockKmsImplementation {}

contract MockDstackKms {
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

/// @dev Models the real KMS authorization direction: KMS delegates the boot
///      decision back to the registered IAppAuth instead of returning an
///      independent test flag.
contract DelegatingMockDstackKms {
    mapping(address => bool) public registeredApps;
    IAppAuth public immutable appAuth;

    constructor(IAppAuth initialAppAuth) {
        appAuth = initialAppAuth;
    }

    function setRegistered(address appId, bool allowed) external {
        registeredApps[appId] = allowed;
    }

    function isAppAllowed(IAppAuth.AppBootInfo calldata bootInfo)
        external
        view
        returns (bool isAllowed, string memory reason)
    {
        return appAuth.isAppAllowed(bootInfo);
    }
}

contract EmailOracleAuthTest is Test {
    EmailOracleAuth internal auth;
    MockDstackKms internal kms;
    MockKmsImplementation internal kmsImplementation;

    address internal owner = makeAddr("owner");
    address internal other = makeAddr("other");
    address internal manager = makeAddr("manager");
    address internal consumer = makeAddr("consumer");

    bytes32 internal initialComposeHash = keccak256("oracle-compose-v1");
    bytes32 internal nextComposeHash = keccak256("oracle-compose-v2");
    bytes32 internal deviceId = keccak256("device-1");
    bytes32 internal consumerComposeHash = keccak256("delegate-compose-v1");

    function setUp() public {
        auth = new EmailOracleAuth(owner, 2 days, true, bytes32(0), initialComposeHash, false);
        kms = new MockDstackKms();
        kmsImplementation = new MockKmsImplementation();
    }

    function _bootInfo(address appId, bytes32 composeHash, bytes32 bootDeviceId)
        internal
        pure
        returns (IAppAuth.AppBootInfo memory info)
    {
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

    function _releaseBootInfo() internal view returns (IAppAuth.AppBootInfo memory info) {
        info = IAppAuth.AppBootInfo({
            appId: address(auth),
            composeHash: initialComposeHash,
            instanceId: address(0x1234),
            deviceId: deviceId,
            mrAggregated: keccak256("mr-aggregated"),
            mrSystem: keccak256("mr-system"),
            osImageHash: keccak256("os-image"),
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });
    }

    function _freezeExactOraclePolicy() internal {
        vm.startPrank(owner);
        auth.setAllowAnyDevice(false);
        auth.addDevice(deviceId);
        auth.freezeOracleCodeAuth(initialComposeHash, deviceId);
        vm.stopPrank();
    }

    function _activateAndFreezeKmsBinding() internal {
        kms.setRegistered(address(auth), true);
        vm.roll(100);
        bytes32 registrationBlockHash = keccak256("registration-block");
        vm.setBlockhash(99, registrationBlockHash);
        vm.prank(owner);
        auth.proposeKmsBinding(
            address(kms),
            address(kms).codehash,
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("registration-tx"),
            99,
            registrationBlockHash,
            _releaseBootInfo(),
            keccak256("independently-verified-restart-key-proof")
        );
        vm.warp(block.timestamp + 2 days);
        auth.activateAndFreezeKmsBinding(_releaseBootInfo());
    }

    function _freezeExactRelease() internal {
        _freezeExactOraclePolicy();
        vm.startPrank(owner);
        auth.setConsumerManager(consumer, true);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.freezeConsumerManagerAdditions(consumer);
        auth.freezeConsumerRegistry(consumer, consumerComposeHash);
        vm.stopPrank();
        _activateAndFreezeKmsBinding();
    }

    function test_InitialComposeHashIsAllowed() public {
        (bool allowed, string memory reason) =
            auth.isAppAllowed(_bootInfo(address(auth), initialComposeHash, bytes32(0)));

        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_FreshSuiteDenyAllPostureHasNoPreboundCvmPolicy() public {
        EmailOracleAuth denyAll = new EmailOracleAuth(owner, 2 days, false, bytes32(0), bytes32(0), true);

        assertEq(denyAll.owner(), owner);
        assertTrue(denyAll.productionRelease());
        assertEq(denyAll.ORACLE_UPGRADE_DELAY(), 2 days);
        assertFalse(denyAll.allowAnyDevice());
        assertFalse(denyAll.oracleCodeFrozen());
        assertFalse(denyAll.consumerRegistryFrozen());
        assertFalse(denyAll.allowedOracleComposeHashes(bytes32(0)));
        assertFalse(denyAll.allowedDeviceIds(bytes32(0)));
        assertFalse(denyAll.isConsumerAuthorized(consumer, consumerComposeHash));

        (bool allowed, string memory reason) =
            denyAll.isAppAllowed(_bootInfo(address(denyAll), initialComposeHash, deviceId));
        assertFalse(allowed);
        assertEq(reason, "Release not ready");
    }

    function test_ProductionAppAuthDeniesRegisteredBootPolicyUntilExactReleaseReady() public {
        EmailOracleAuth production = new EmailOracleAuth(owner, 2 days, false, deviceId, initialComposeHash, true);

        (bool allowed, string memory reason) =
            production.isAppAllowed(_bootInfo(address(production), initialComposeHash, deviceId));
        assertFalse(allowed);
        assertEq(reason, "Release not ready");

        vm.prank(owner);
        production.transferOwnership(other);
        (allowed, reason) = production.isAppAllowed(_bootInfo(address(production), initialComposeHash, deviceId));
        assertFalse(allowed);
        assertEq(reason, "Release not ready");
    }

    function test_ProductionConsumerPolicyIsOnlyStagedUntilFinalReleaseSeal() public {
        EmailOracleAuth production = new EmailOracleAuth(owner, 2 days, false, bytes32(0), bytes32(0), true);

        vm.startPrank(owner);
        production.setConsumerManager(consumer, true);
        production.addConsumerComposeHash(consumer, consumerComposeHash);
        vm.stopPrank();

        assertTrue(production.isConsumerComposeHashRegistered(consumer, consumerComposeHash));
        assertFalse(production.isConsumerAuthorized(consumer, consumerComposeHash));
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.ReleaseConfigurationIncomplete.selector);
        production.recordOtpDelivery(consumer, keccak256("staged-only"));
        assertEq(production.otpDeliveryCount(consumer), 0);
    }

    function test_ConstructorRejectsUnsafeUpgradeDelayAndPrecomputedSelfOwner() public {
        vm.expectRevert(EmailOracleAuth.InvalidUpgradeDelay.selector);
        new EmailOracleAuth(owner, 2 days - 1, false, bytes32(0), bytes32(0), true);

        vm.expectRevert(EmailOracleAuth.InvalidUpgradeDelay.selector);
        new EmailOracleAuth(owner, 365 days + 1, false, bytes32(0), bytes32(0), true);

        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(EmailOracleAuth.RoleCollision.selector);
        new EmailOracleAuth(predicted, 2 days, false, bytes32(0), bytes32(0), true);
    }

    function test_IsAppAllowed_RejectsWrongAppId() public {
        (bool allowed, string memory reason) =
            auth.isAppAllowed(_bootInfo(address(0xBEEF), initialComposeHash, bytes32(0)));

        assertFalse(allowed);
        assertEq(reason, "App ID mismatch");
    }

    function test_ProposeAndActivateOracleComposeHash() public {
        vm.prank(owner);
        auth.proposeOracleComposeHash(nextComposeHash);

        vm.warp(block.timestamp + 2 days);
        auth.activateOracleComposeHash(nextComposeHash);

        (bool allowed, string memory reason) = auth.isAppAllowed(_bootInfo(address(auth), nextComposeHash, bytes32(0)));
        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_ActivateOracleComposeHash_RevertTooEarly() public {
        vm.prank(owner);
        auth.proposeOracleComposeHash(nextComposeHash);

        vm.expectRevert(abi.encodeWithSelector(EmailOracleAuth.ActivationTooEarly.selector, block.timestamp + 2 days));
        auth.activateOracleComposeHash(nextComposeHash);
    }

    function test_DeviceRestriction() public {
        vm.startPrank(owner);
        auth.setAllowAnyDevice(false);
        auth.addDevice(deviceId);
        vm.stopPrank();

        (bool allowedWrongDevice,) =
            auth.isAppAllowed(_bootInfo(address(auth), initialComposeHash, keccak256("other-device")));
        assertFalse(allowedWrongDevice);

        (bool allowedRightDevice,) = auth.isAppAllowed(_bootInfo(address(auth), initialComposeHash, deviceId));
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
        _freezeExactOraclePolicy();

        vm.prank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);

        assertTrue(auth.oracleCodeFrozen());
        assertTrue(auth.isConsumerAuthorized(consumer, consumerComposeHash));

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.OracleCodeFrozen.selector);
        auth.proposeOracleComposeHash(nextComposeHash);
    }

    function test_FreezeConsumerRegistry_BlocksOwnerAndManager() public {
        _freezeExactRelease();

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.ConsumerRegistryFrozen.selector);
        auth.removeConsumerComposeHash(consumer, consumerComposeHash);

        vm.prank(consumer);
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
        _freezeExactOraclePolicy();

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.OracleCodeFrozen.selector);
        auth.addDevice(keccak256("new-device"));
    }

    function test_FreezeOracleCodeAuthRequiresExactCountsAndNoPendingProposal() public {
        vm.startPrank(owner);
        auth.setAllowAnyDevice(false);
        auth.addDevice(deviceId);
        bytes32 extraDevice = keccak256("extra-device");
        auth.addDevice(extraDevice);
        vm.expectRevert(EmailOracleAuth.ReleaseConfigurationIncomplete.selector);
        auth.freezeOracleCodeAuth(initialComposeHash, deviceId);
        auth.removeDevice(extraDevice);

        auth.proposeOracleComposeHash(nextComposeHash);
        vm.expectRevert(EmailOracleAuth.ReleaseConfigurationIncomplete.selector);
        auth.freezeOracleCodeAuth(initialComposeHash, deviceId);
        auth.cancelOracleComposeHashProposal(nextComposeHash);

        auth.freezeOracleCodeAuth(initialComposeHash, deviceId);
        vm.stopPrank();

        assertEq(auth.allowedOracleComposeHashCount(), 1);
        assertEq(auth.pendingOracleComposeHashCount(), 0);
        assertEq(auth.allowedDeviceIdCount(), 1);
    }

    function test_EmergencyOracleRemovalsRemainAvailableAndPermanentAfterFreeze() public {
        _freezeExactRelease();
        assertTrue(auth.releaseConfigurationReady());

        vm.startPrank(owner);
        auth.removeOracleComposeHash(initialComposeHash);
        auth.removeDevice(deviceId);
        assertFalse(auth.releaseConfigurationReady());
        vm.expectRevert(EmailOracleAuth.OracleCodeFrozen.selector);
        auth.proposeOracleComposeHash(initialComposeHash);
        vm.expectRevert(EmailOracleAuth.OracleCodeFrozen.selector);
        auth.addDevice(deviceId);
        vm.stopPrank();

        (bool allowed,) = auth.isAppAllowed(_releaseBootInfo());
        assertFalse(allowed);
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

        (bool allowed,) = auth.isAppAllowed(_bootInfo(address(auth), nextComposeHash, bytes32(0)));
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

        (bool allowed,) = auth.isAppAllowed(_bootInfo(address(auth), nextComposeHash, bytes32(0)));
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

        (bool blocked,) = auth.isAppAllowed(_bootInfo(address(auth), initialComposeHash, keccak256("unknown-device")));
        assertFalse(blocked);

        vm.prank(owner);
        auth.setAllowAnyDevice(true);
        (bool nowAllowed,) =
            auth.isAppAllowed(_bootInfo(address(auth), initialComposeHash, keccak256("unknown-device")));
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
        assertEq(auth.owner(), owner);
        assertEq(auth.pendingOwner(), other);

        vm.prank(other);
        auth.acceptOwnership();
        assertEq(auth.owner(), other);
        assertEq(auth.pendingOwner(), address(0));

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

    function test_TwoStepOwnershipRejectsDelegatedRoleCollisions() public {
        vm.prank(owner);
        auth.setConsumerManager(manager, true);
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.RoleCollision.selector);
        auth.transferOwnership(manager);

        vm.prank(owner);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.RoleCollision.selector);
        auth.transferOwnership(consumer);

        vm.prank(owner);
        auth.transferOwnership(other);
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.RoleCollision.selector);
        auth.setConsumerManager(other, true);
        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.RoleCollision.selector);
        auth.addConsumerComposeHash(other, keccak256("pending-owner-policy"));
        vm.prank(manager);
        vm.expectRevert(EmailOracleAuth.NotPendingOwner.selector);
        auth.acceptOwnership();
    }

    function test_OwnerCanCancelPendingOwnershipTransfer() public {
        vm.startPrank(owner);
        auth.transferOwnership(other);
        auth.cancelOwnershipTransfer();
        vm.stopPrank();
        assertEq(auth.owner(), owner);
        assertEq(auth.pendingOwner(), address(0));
        vm.prank(other);
        vm.expectRevert(EmailOracleAuth.NotPendingOwner.selector);
        auth.acceptOwnership();
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
        _freezeExactRelease();
        vm.startPrank(owner);
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
        _freezeExactRelease();
        vm.startPrank(owner);
        auth.emergencyRevokeConsumer(consumer);
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

    function test_KmsBindingFailsClosedWithoutRegistrationOrBootAuthorization() public {
        _freezeExactOraclePolicy();
        vm.startPrank(owner);
        auth.setConsumerManager(consumer, true);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.freezeConsumerManagerAdditions(consumer);
        auth.freezeConsumerRegistry(consumer, consumerComposeHash);
        vm.stopPrank();

        vm.roll(100);
        bytes32 registrationBlockHash = keccak256("registration-block");
        vm.setBlockhash(99, registrationBlockHash);

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.KmsRegistrationMissing.selector);
        auth.proposeKmsBinding(
            address(kms),
            address(kms).codehash,
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("registration-tx"),
            99,
            registrationBlockHash,
            _releaseBootInfo(),
            keccak256("restart-proof")
        );

        kms.setRegistered(address(auth), true);
        kms.setBootAllowed(false);
        vm.prank(owner);
        auth.proposeKmsBinding(
            address(kms),
            address(kms).codehash,
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("registration-tx"),
            99,
            registrationBlockHash,
            _releaseBootInfo(),
            keccak256("restart-proof")
        );

        uint256 activatesAt = auth.pendingKmsBindingActivatesAt();
        vm.warp(activatesAt);
        vm.expectRevert(EmailOracleAuth.KmsBootAuthorizationDenied.selector);
        auth.activateAndFreezeKmsBinding(_releaseBootInfo());

        // Failed activation rolls every tentative binding write back atomically
        // while retaining the reviewed pending proposal for a later retry.
        assertFalse(auth.kmsBindingFrozen());
        assertEq(auth.kmsContract(), address(0));
        assertEq(auth.pendingKmsBindingActivatesAt(), activatesAt);
        assertEq(auth.pendingKmsContract(), address(kms));
        assertFalse(auth.releaseConfigurationReady());

        kms.setBootAllowed(true);
        auth.activateAndFreezeKmsBinding(_releaseBootInfo());
        assertTrue(auth.kmsBindingFrozen());
        assertEq(auth.kmsContract(), address(kms));
        assertEq(auth.pendingKmsBindingActivatesAt(), 0);
        assertTrue(auth.releaseConfigurationReady());
    }

    function test_KmsBindingRejectsCodeHashAndRegistrationBlockDrift() public {
        _freezeExactOraclePolicy();
        kms.setRegistered(address(auth), true);
        vm.roll(400);
        bytes32 registrationBlockHash = keccak256("registration-block");
        vm.setBlockhash(399, registrationBlockHash);

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.RuntimeCodeHashMismatch.selector);
        auth.proposeKmsBinding(
            address(kms),
            keccak256("wrong-runtime"),
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("registration-tx"),
            399,
            registrationBlockHash,
            _releaseBootInfo(),
            keccak256("restart-proof")
        );

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.RegistrationBlockUnavailable.selector);
        auth.proposeKmsBinding(
            address(kms),
            address(kms).codehash,
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("registration-tx"),
            400,
            keccak256("future-or-current-block"),
            _releaseBootInfo(),
            keccak256("restart-proof")
        );
    }

    function test_KmsActivationRechecksRegistrationAfterTimelock() public {
        _freezeExactOraclePolicy();
        kms.setRegistered(address(auth), true);
        vm.roll(100);
        bytes32 registrationBlockHash = keccak256("registration-block");
        vm.setBlockhash(99, registrationBlockHash);
        vm.prank(owner);
        auth.proposeKmsBinding(
            address(kms),
            address(kms).codehash,
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("registration-tx"),
            99,
            registrationBlockHash,
            _releaseBootInfo(),
            keccak256("restart-proof")
        );

        vm.warp(block.timestamp + 2 days);
        kms.setRegistered(address(auth), false);
        vm.expectRevert(EmailOracleAuth.KmsRegistrationMissing.selector);
        auth.activateAndFreezeKmsBinding(_releaseBootInfo());
    }

    function test_ExactReleaseBindsEnumerablePolicyAndKmsEvidence() public {
        _freezeExactRelease();

        assertTrue(auth.releaseConfigurationReady());
        assertEq(auth.releaseOracleComposeHash(), initialComposeHash);
        assertEq(auth.releaseDeviceId(), deviceId);
        assertEq(auth.releaseConsumerManager(), consumer);
        assertEq(auth.releaseConsumerAppId(), consumer);
        assertEq(auth.releaseConsumerComposeHash(), consumerComposeHash);
        assertEq(auth.allowedOracleComposeHashCount(), 1);
        assertEq(auth.pendingOracleComposeHashCount(), 0);
        assertEq(auth.allowedDeviceIdCount(), 1);
        assertEq(auth.consumerManagerCount(), 1);
        assertEq(auth.totalConsumerComposeHashCount(), 1);
        assertTrue(auth.oracleCodeFrozen());
        assertTrue(auth.consumerManagerAdditionsFrozen());
        assertTrue(auth.consumerRegistryFrozen());
        assertTrue(auth.kmsBindingFrozen());
        assertEq(auth.kmsContract(), address(kms));
        assertEq(auth.kmsRuntimeCodeHash(), address(kms).codehash);
        assertEq(auth.kmsImplementation(), address(kmsImplementation));
        assertEq(auth.kmsImplementationRuntimeCodeHash(), address(kmsImplementation).codehash);
        assertEq(auth.kmsRegistrationTxHash(), keccak256("registration-tx"));
        assertEq(auth.kmsRegistrationBlock(), 99);
        assertEq(auth.kmsRegistrationBlockHash(), keccak256("registration-block"));
        assertEq(auth.targetBootInfoHash(), keccak256(abi.encode(_releaseBootInfo())));
        assertEq(auth.restartKeyDerivationProofHash(), keccak256("independently-verified-restart-key-proof"));
    }

    function test_ProductionAppAuthDynamicallyDeniesAfterFrozenEmergencyRevocation() public {
        auth = new EmailOracleAuth(owner, 2 days, true, bytes32(0), initialComposeHash, true);
        _freezeExactRelease();

        (bool allowed, string memory reason) = auth.isAppAllowed(_releaseBootInfo());
        assertTrue(allowed);
        assertEq(reason, "");

        vm.prank(owner);
        auth.emergencyRevokeConsumer(consumer);
        assertFalse(auth.releaseConfigurationReady());
        (allowed, reason) = auth.isAppAllowed(_releaseBootInfo());
        assertFalse(allowed);
        assertEq(reason, "Release not ready");
    }

    function test_ProductionAppAuthDeniesWhileKmsBindingIsPending() public {
        auth = new EmailOracleAuth(owner, 2 days, true, bytes32(0), initialComposeHash, true);
        _freezeExactOraclePolicy();
        kms.setRegistered(address(auth), true);
        vm.roll(100);
        bytes32 registrationBlockHash = keccak256("pending-registration-block");
        vm.setBlockhash(99, registrationBlockHash);
        vm.prank(owner);
        auth.proposeKmsBinding(
            address(kms),
            address(kms).codehash,
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("pending-registration-tx"),
            99,
            registrationBlockHash,
            _releaseBootInfo(),
            keccak256("pending-restart-proof")
        );

        (bool allowed, string memory reason) = auth.isAppAllowed(_releaseBootInfo());
        assertFalse(allowed);
        assertEq(reason, "Release not ready");
    }

    function test_DelegatingKmsIsDeniedBeforeFreezeAndAllowedOnlyAfterAtomicFinalization() public {
        auth = new EmailOracleAuth(owner, 2 days, true, bytes32(0), initialComposeHash, true);
        DelegatingMockDstackKms delegatingKms = new DelegatingMockDstackKms(IAppAuth(address(auth)));
        delegatingKms.setRegistered(address(auth), true);

        (bool allowed, string memory reason) = delegatingKms.isAppAllowed(_releaseBootInfo());
        assertFalse(allowed);
        assertEq(reason, "Release not ready");

        _freezeExactOraclePolicy();
        vm.startPrank(owner);
        auth.setConsumerManager(consumer, true);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.freezeConsumerManagerAdditions(consumer);
        auth.freezeConsumerRegistry(consumer, consumerComposeHash);
        vm.stopPrank();

        vm.roll(200);
        bytes32 registrationBlockHash = keccak256("delegating-registration-block");
        vm.setBlockhash(199, registrationBlockHash);
        vm.prank(owner);
        auth.proposeKmsBinding(
            address(delegatingKms),
            address(delegatingKms).codehash,
            address(kmsImplementation),
            address(kmsImplementation).codehash,
            keccak256("delegating-registration-tx"),
            199,
            registrationBlockHash,
            _releaseBootInfo(),
            keccak256("delegating-restart-proof")
        );

        (allowed, reason) = delegatingKms.isAppAllowed(_releaseBootInfo());
        assertFalse(allowed);
        assertEq(reason, "Release not ready");

        vm.warp(block.timestamp + 2 days);
        auth.activateAndFreezeKmsBinding(_releaseBootInfo());

        assertTrue(auth.releaseConfigurationReady());
        (allowed, reason) = delegatingKms.isAppAllowed(_releaseBootInfo());
        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_ManagerRemovalAfterFreezeIsPermanentAndMakesReleaseUnready() public {
        _freezeExactRelease();
        vm.startPrank(owner);
        auth.setConsumerManager(consumer, false);
        assertFalse(auth.releaseConfigurationReady());
        vm.expectRevert(EmailOracleAuth.ConsumerManagerAdditionsFrozen.selector);
        auth.setConsumerManager(consumer, true);
        vm.stopPrank();
    }

    function test_FinalConsumerFreezeRejectsExtraPolicyAndMissingKmsBinding() public {
        auth = new EmailOracleAuth(owner, 2 days, true, bytes32(0), initialComposeHash, true);
        _freezeExactOraclePolicy();
        vm.startPrank(owner);
        auth.setConsumerManager(consumer, true);
        auth.addConsumerComposeHash(consumer, consumerComposeHash);
        auth.freezeConsumerManagerAdditions(consumer);
        auth.freezeConsumerRegistry(consumer, consumerComposeHash);
        vm.stopPrank();

        // Raw membership is sealed before KMS finalization, but production
        // authorization remains deny-all until the exact KMS binding is live.
        assertTrue(auth.consumerRegistryFrozen());
        assertTrue(auth.isConsumerComposeHashRegistered(consumer, consumerComposeHash));
        assertFalse(auth.isConsumerAuthorized(consumer, consumerComposeHash));
        assertFalse(auth.releaseConfigurationReady());

        vm.prank(owner);
        vm.expectRevert(EmailOracleAuth.ConsumerRegistryFrozen.selector);
        auth.addConsumerComposeHash(manager, keccak256("extra-policy"));

        _activateAndFreezeKmsBinding();
        assertTrue(auth.releaseConfigurationReady());
        assertTrue(auth.isConsumerAuthorized(consumer, consumerComposeHash));
    }

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
