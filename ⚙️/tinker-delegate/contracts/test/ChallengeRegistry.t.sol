// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ChallengeRegistry} from "../src/ChallengeRegistry.sol";

contract ChallengeRegistryTest is Test {
    ChallengeRegistry internal registry;

    address internal owner = makeAddr("owner");
    address internal registrar = makeAddr("registrar");
    address internal controller = makeAddr("controller");
    address internal nextController = makeAddr("next-controller");
    address internal stranger = makeAddr("stranger");

    function setUp() public {
        registry = new ChallengeRegistry(owner);
        vm.prank(owner);
        registry.setRegistrar(registrar, true);
    }

    function _version(bytes32 salt) internal pure returns (ChallengeRegistry.VersionInput memory input) {
        input = ChallengeRegistry.VersionInput({
            metadataURI: "ipfs://bafy-challenge-metadata",
            metadataHash: keccak256(abi.encode("metadata", salt)),
            sealedArtifactCommitment: keccak256(abi.encode("sealed-artifact", salt)),
            evaluatorCommitment: keccak256(abi.encode("evaluator", salt)),
            releasePolicyCommitment: keccak256(abi.encode("release-policy", salt))
        });
    }

    function _create() internal returns (uint256 challengeId) {
        vm.prank(registrar);
        challengeId = registry.createChallenge(controller, _version(keccak256("v1")));
    }

    function _freeze(uint256 challengeId) internal {
        vm.warp(registry.reviewEligibleAt(challengeId));
        vm.prank(controller);
        registry.freezeChallengeConfiguration(challengeId);
    }

    function test_ConstructorSetsExplicitOwnerAndStartsEmpty() public view {
        assertEq(registry.owner(), owner);
        assertEq(registry.nextChallengeId(), 1);
        assertEq(registry.challengeCount(), 0);
        assertFalse(registry.registryPaused());
    }

    function test_ConstructorRejectsZeroAndSelfOwner() public {
        vm.expectRevert(ChallengeRegistry.ZeroAddress.selector);
        new ChallengeRegistry(address(0));

        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(ChallengeRegistry.SelfAddress.selector);
        new ChallengeRegistry(predicted);
    }

    function test_OwnershipTransferIsExactTwoStepAndCannotSelfLock() public {
        vm.prank(owner);
        vm.expectRevert(ChallengeRegistry.SelfAddress.selector);
        registry.transferOwnership(address(registry));

        vm.prank(owner);
        registry.transferOwnership(nextController);
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), nextController);

        vm.prank(owner);
        vm.expectRevert(ChallengeRegistry.NoStateChange.selector);
        registry.transferOwnership(nextController);

        vm.prank(stranger);
        vm.expectRevert(ChallengeRegistry.NotPendingOwner.selector);
        registry.acceptOwnership();
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), nextController);

        vm.prank(nextController);
        registry.acceptOwnership();
        assertEq(registry.owner(), nextController);
        assertEq(registry.pendingOwner(), address(0));

        vm.prank(owner);
        vm.expectRevert(ChallengeRegistry.NotOwner.selector);
        registry.setRegistrar(stranger, true);
    }

    function test_OwnershipAndRegistrarGuards() public {
        vm.prank(stranger);
        vm.expectRevert(ChallengeRegistry.NotOwner.selector);
        registry.setRegistrar(stranger, true);

        vm.prank(owner);
        vm.expectRevert(ChallengeRegistry.ZeroAddress.selector);
        registry.setRegistrar(address(0), true);

        vm.prank(owner);
        vm.expectRevert(ChallengeRegistry.NoStateChange.selector);
        registry.setRegistrar(registrar, true);

        vm.prank(owner);
        vm.expectRevert(ChallengeRegistry.NoStateChange.selector);
        registry.transferOwnership(owner);
    }

    function test_RegistrarCanCreateVersionOne() public {
        uint256 challengeId = _create();

        ChallengeRegistry.Challenge memory challenge = registry.getChallenge(challengeId);
        ChallengeRegistry.ChallengeVersion memory version = registry.getVersion(challengeId, 1);
        assertEq(challengeId, 1);
        assertEq(challenge.controller, controller);
        assertEq(uint8(challenge.lifecycle), uint8(ChallengeRegistry.Lifecycle.Draft));
        assertEq(challenge.latestVersion, 1);
        assertFalse(challenge.paused);
        assertFalse(challenge.configurationFrozen);
        assertEq(version.metadataURI, "ipfs://bafy-challenge-metadata");
        assertEq(version.metadataHash, _version(keccak256("v1")).metadataHash);
        assertTrue(version.createdAt > 0);
        assertEq(registry.reviewEligibleAt(challengeId), version.createdAt + registry.MIN_VERSION_REVIEW_DELAY());
        assertEq(registry.challengeCount(), 1);
        assertTrue(registry.challengeExists(challengeId));
    }

    function test_OwnerIsImplicitRegistrar() public {
        vm.prank(owner);
        uint256 challengeId = registry.createChallenge(controller, _version(keccak256("owner")));
        assertEq(challengeId, 1);
    }

    function test_NonRegistrarCannotCreate() public {
        vm.prank(stranger);
        vm.expectRevert(ChallengeRegistry.NotRegistrar.selector);
        registry.createChallenge(controller, _version(keccak256("unauthorized")));
    }

    function test_CreateRejectsZeroControllerAndBadMetadata() public {
        vm.startPrank(registrar);
        vm.expectRevert(ChallengeRegistry.ZeroAddress.selector);
        registry.createChallenge(address(0), _version(keccak256("zero-controller")));

        vm.expectRevert(ChallengeRegistry.SelfAddress.selector);
        registry.createChallenge(address(registry), _version(keccak256("self-controller")));

        ChallengeRegistry.VersionInput memory input = _version(keccak256("empty-uri"));
        input.metadataURI = "";
        vm.expectRevert(ChallengeRegistry.EmptyMetadataURI.selector);
        registry.createChallenge(controller, input);

        input = _version(keccak256("long-uri"));
        input.metadataURI = new string(registry.MAX_METADATA_URI_BYTES() + 1);
        vm.expectRevert(ChallengeRegistry.MetadataURITooLong.selector);
        registry.createChallenge(controller, input);
        vm.stopPrank();
    }

    function test_CreateRejectsEveryZeroCommitmentField() public {
        ChallengeRegistry.VersionInput memory input = _version(keccak256("zero-fields"));
        vm.startPrank(registrar);

        input.metadataHash = bytes32(0);
        vm.expectRevert(ChallengeRegistry.ZeroCommitment.selector);
        registry.createChallenge(controller, input);

        input = _version(keccak256("zero-fields"));
        input.sealedArtifactCommitment = bytes32(0);
        vm.expectRevert(ChallengeRegistry.ZeroCommitment.selector);
        registry.createChallenge(controller, input);

        input = _version(keccak256("zero-fields"));
        input.evaluatorCommitment = bytes32(0);
        vm.expectRevert(ChallengeRegistry.ZeroCommitment.selector);
        registry.createChallenge(controller, input);

        input = _version(keccak256("zero-fields"));
        input.releasePolicyCommitment = bytes32(0);
        vm.expectRevert(ChallengeRegistry.ZeroCommitment.selector);
        registry.createChallenge(controller, input);
        vm.stopPrank();
    }

    function test_ControllerAddsImmutableVersions() public {
        uint256 challengeId = _create();
        ChallengeRegistry.ChallengeVersion memory first = registry.getVersion(challengeId, 1);

        vm.warp(block.timestamp + 10);
        ChallengeRegistry.VersionInput memory secondInput = _version(keccak256("v2"));
        vm.prank(controller);
        uint32 version = registry.addVersion(challengeId, secondInput);

        ChallengeRegistry.Challenge memory challenge = registry.getChallenge(challengeId);
        ChallengeRegistry.ChallengeVersion memory firstAfter = registry.getVersion(challengeId, 1);
        ChallengeRegistry.ChallengeVersion memory second = registry.latestVersion(challengeId);
        assertEq(version, 2);
        assertEq(challenge.latestVersion, 2);
        assertEq(firstAfter.metadataHash, first.metadataHash);
        assertEq(second.metadataHash, secondInput.metadataHash);
        assertEq(second.createdAt, block.timestamp);
    }

    function test_LatestVersionRequiresFullPublicReviewWindowBeforeFreeze() public {
        uint256 challengeId = _create();
        uint64 eligibleAt = registry.reviewEligibleAt(challengeId);

        vm.prank(controller);
        vm.expectRevert(abi.encodeWithSelector(ChallengeRegistry.ChallengeReviewPending.selector, eligibleAt));
        registry.freezeChallengeConfiguration(challengeId);

        vm.warp(eligibleAt - 1);
        vm.prank(controller);
        vm.expectRevert(abi.encodeWithSelector(ChallengeRegistry.ChallengeReviewPending.selector, eligibleAt));
        registry.freezeChallengeConfiguration(challengeId);

        vm.warp(eligibleAt);
        vm.prank(controller);
        registry.freezeChallengeConfiguration(challengeId);
        assertTrue(registry.getChallenge(challengeId).configurationFrozen);
    }

    function test_AddingVersionRestartsReviewWindowAndPreventsLastBlockAmbush() public {
        uint256 challengeId = _create();
        uint64 firstEligibleAt = registry.reviewEligibleAt(challengeId);
        vm.warp(firstEligibleAt);

        vm.prank(controller);
        registry.addVersion(challengeId, _version(keccak256("late-v2")));
        uint64 secondEligibleAt = registry.reviewEligibleAt(challengeId);
        assertEq(secondEligibleAt, firstEligibleAt + registry.MIN_VERSION_REVIEW_DELAY());

        vm.prank(controller);
        vm.expectRevert(abi.encodeWithSelector(ChallengeRegistry.ChallengeReviewPending.selector, secondEligibleAt));
        registry.freezeChallengeConfiguration(challengeId);

        vm.warp(secondEligibleAt);
        vm.prank(controller);
        registry.freezeChallengeConfiguration(challengeId);
        assertEq(registry.getChallenge(challengeId).latestVersion, 2);
    }

    function test_NonControllerCannotVersionFreezeOrChangeLifecycle() public {
        uint256 challengeId = _create();
        vm.startPrank(stranger);
        vm.expectRevert(ChallengeRegistry.NotChallengeController.selector);
        registry.addVersion(challengeId, _version(keccak256("v2")));
        vm.expectRevert(ChallengeRegistry.NotChallengeController.selector);
        registry.freezeChallengeConfiguration(challengeId);
        vm.expectRevert(ChallengeRegistry.NotChallengeController.selector);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Cancelled);
        vm.stopPrank();
    }

    function test_OwnerCanActAsEmergencyChallengeController() public {
        uint256 challengeId = _create();
        vm.warp(registry.reviewEligibleAt(challengeId));
        vm.prank(owner);
        registry.freezeChallengeConfiguration(challengeId);
        vm.prank(owner);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Open);
        assertEq(uint8(registry.getChallenge(challengeId).lifecycle), uint8(ChallengeRegistry.Lifecycle.Open));
    }

    function test_ConfigurationMustFreezeBeforeOpenAndThenCannotChange() public {
        uint256 challengeId = _create();
        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.ChallengeConfigurationNotFrozen.selector);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Open);

        _freeze(challengeId);
        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.ChallengeConfigurationFrozenError.selector);
        registry.addVersion(challengeId, _version(keccak256("too-late")));
        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.ChallengeConfigurationFrozenError.selector);
        registry.transferChallengeController(challengeId, nextController);

        vm.prank(controller);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Open);
        assertTrue(registry.getChallenge(challengeId).configurationFrozen);
    }

    function test_LifecycleOpenCloseArchive() public {
        uint256 challengeId = _create();
        _freeze(challengeId);

        vm.startPrank(controller);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Open);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Closed);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Archived);
        vm.stopPrank();

        assertEq(uint8(registry.getChallenge(challengeId).lifecycle), uint8(ChallengeRegistry.Lifecycle.Archived));
    }

    function test_LifecycleCancelAndArchiveFromDraft() public {
        uint256 challengeId = _create();
        vm.startPrank(controller);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Cancelled);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Archived);
        vm.stopPrank();
        assertEq(uint8(registry.getChallenge(challengeId).lifecycle), uint8(ChallengeRegistry.Lifecycle.Archived));
    }

    function test_InvalidAndDuplicateLifecycleTransitionsRevert() public {
        uint256 challengeId = _create();
        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.NoStateChange.selector);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Draft);

        vm.prank(controller);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChallengeRegistry.InvalidLifecycleTransition.selector,
                ChallengeRegistry.Lifecycle.Draft,
                ChallengeRegistry.Lifecycle.Closed
            )
        );
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Closed);
    }

    function test_ChallengePauseBlocksMutableOperationsButAllowsFreeze() public {
        uint256 challengeId = _create();
        vm.warp(registry.reviewEligibleAt(challengeId));
        vm.prank(controller);
        registry.setChallengePaused(challengeId, true);

        vm.startPrank(controller);
        vm.expectRevert(ChallengeRegistry.ChallengePaused.selector);
        registry.addVersion(challengeId, _version(keccak256("blocked")));
        vm.expectRevert(ChallengeRegistry.ChallengePaused.selector);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Cancelled);
        vm.expectRevert(ChallengeRegistry.ChallengePaused.selector);
        registry.transferChallengeController(challengeId, nextController);

        registry.freezeChallengeConfiguration(challengeId);
        registry.setChallengePaused(challengeId, false);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Open);
        vm.stopPrank();
    }

    function test_GovernancePauseCannotBeClearedByController() public {
        uint256 challengeId = _create();

        vm.prank(owner);
        registry.setChallengePaused(challengeId, true);
        assertTrue(registry.governanceChallengePaused(challengeId));
        assertFalse(registry.controllerChallengePaused(challengeId));
        assertTrue(registry.getChallenge(challengeId).paused);

        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.NoStateChange.selector);
        registry.setChallengePaused(challengeId, false);
        assertTrue(registry.governanceChallengePaused(challengeId));
        assertTrue(registry.getChallenge(challengeId).paused);

        vm.prank(controller);
        registry.setChallengePaused(challengeId, true);
        vm.prank(controller);
        registry.setChallengePaused(challengeId, false);
        assertFalse(registry.controllerChallengePaused(challengeId));
        assertTrue(registry.governanceChallengePaused(challengeId));
        assertTrue(registry.getChallenge(challengeId).paused);

        vm.prank(owner);
        registry.setChallengePaused(challengeId, false);
        assertFalse(registry.governanceChallengePaused(challengeId));
        assertFalse(registry.getChallenge(challengeId).paused);
    }

    function test_ControllerPauseCannotBeClearedByGovernance() public {
        uint256 challengeId = _create();

        vm.prank(controller);
        registry.setChallengePaused(challengeId, true);
        vm.prank(owner);
        registry.setChallengePaused(challengeId, true);

        vm.prank(owner);
        registry.setChallengePaused(challengeId, false);
        assertTrue(registry.controllerChallengePaused(challengeId));
        assertFalse(registry.governanceChallengePaused(challengeId));
        assertTrue(registry.getChallenge(challengeId).paused);

        vm.prank(controller);
        registry.setChallengePaused(challengeId, false);
        assertFalse(registry.getChallenge(challengeId).paused);
    }

    function test_GlobalPauseBlocksActivityButSafetyActionsRemain() public {
        uint256 challengeId = _create();
        vm.warp(registry.reviewEligibleAt(challengeId));
        vm.prank(controller);
        registry.setChallengePaused(challengeId, true);
        vm.prank(owner);
        registry.setRegistryPaused(true);

        vm.prank(registrar);
        vm.expectRevert(ChallengeRegistry.RegistryPaused.selector);
        registry.createChallenge(controller, _version(keccak256("blocked-create")));

        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.RegistryPaused.selector);
        registry.addVersion(challengeId, _version(keccak256("blocked-version")));

        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.RegistryPaused.selector);
        registry.setChallengePaused(challengeId, false);

        vm.prank(controller);
        registry.freezeChallengeConfiguration(challengeId);
        vm.prank(owner);
        registry.setRegistrar(registrar, false);
        assertFalse(registry.registrars(registrar));

        vm.prank(owner);
        vm.expectRevert(ChallengeRegistry.RegistryPaused.selector);
        registry.setRegistrar(stranger, true);
    }

    function test_CanEmergencyPauseChallengeWhileRegistryPaused() public {
        uint256 challengeId = _create();
        vm.prank(owner);
        registry.setRegistryPaused(true);
        vm.prank(controller);
        registry.setChallengePaused(challengeId, true);
        assertTrue(registry.getChallenge(challengeId).paused);
    }

    function test_CannotPauseTerminalChallenge() public {
        uint256 challengeId = _create();
        vm.prank(controller);
        registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Cancelled);
        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.InvalidLifecycleForOperation.selector);
        registry.setChallengePaused(challengeId, true);
    }

    function test_ControllerTransferIsExactTwoStepCancellableAndCannotSelfLock() public {
        uint256 challengeId = _create();

        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.SelfAddress.selector);
        registry.transferChallengeController(challengeId, address(registry));
        assertEq(registry.getChallenge(challengeId).controller, controller);
        assertEq(registry.getChallenge(challengeId).pendingController, address(0));

        vm.prank(controller);
        registry.transferChallengeController(challengeId, nextController);
        assertEq(registry.getChallenge(challengeId).controller, controller);
        assertEq(registry.getChallenge(challengeId).pendingController, nextController);

        vm.prank(controller);
        vm.expectRevert(ChallengeRegistry.NoStateChange.selector);
        registry.transferChallengeController(challengeId, nextController);

        vm.prank(stranger);
        vm.expectRevert(ChallengeRegistry.NotChallengeController.selector);
        registry.acceptChallengeController(challengeId);
        assertEq(registry.getChallenge(challengeId).controller, controller);
        assertEq(registry.getChallenge(challengeId).pendingController, nextController);

        vm.prank(nextController);
        registry.acceptChallengeController(challengeId);
        assertEq(registry.getChallenge(challengeId).controller, nextController);
        assertEq(registry.getChallenge(challengeId).pendingController, address(0));

        vm.prank(nextController);
        registry.transferChallengeController(challengeId, controller);
        vm.prank(nextController);
        registry.cancelChallengeControllerTransfer(challengeId);
        assertEq(registry.getChallenge(challengeId).pendingController, address(0));
    }

    function test_FreezeCancelsPendingControllerTransfer() public {
        uint256 challengeId = _create();
        vm.prank(controller);
        registry.transferChallengeController(challengeId, nextController);
        _freeze(challengeId);
        assertEq(registry.getChallenge(challengeId).pendingController, address(0));

        vm.prank(nextController);
        vm.expectRevert(ChallengeRegistry.ChallengeConfigurationFrozenError.selector);
        registry.acceptChallengeController(challengeId);
    }

    function test_GettersRejectMissingChallengeAndVersion() public {
        vm.expectRevert(ChallengeRegistry.ChallengeNotFound.selector);
        registry.getChallenge(999);

        uint256 challengeId = _create();
        vm.expectRevert(ChallengeRegistry.VersionNotFound.selector);
        registry.getVersion(challengeId, 0);
        vm.expectRevert(ChallengeRegistry.VersionNotFound.selector);
        registry.getVersion(challengeId, 2);
    }

    function test_NoNativeCustodyReceiveOrFallback() public {
        vm.deal(stranger, 2 ether);
        vm.startPrank(stranger);
        (bool receiveOk, bytes memory receiveData) = address(registry).call{value: 1 ether}("");
        (bool fallbackOk, bytes memory fallbackData) = address(registry).call{value: 1 ether}(hex"deadbeef");
        vm.stopPrank();

        assertFalse(receiveOk);
        assertFalse(fallbackOk);
        assertEq(keccak256(receiveData), keccak256(abi.encodeWithSelector(ChallengeRegistry.NoCustody.selector)));
        assertEq(keccak256(fallbackData), keccak256(abi.encodeWithSelector(ChallengeRegistry.NoCustody.selector)));
        assertEq(address(registry).balance, 0);
    }

    function testFuzz_ValidMetadataUriLengthsAreAccepted(uint16 rawLength) public {
        uint256 uriLength = bound(rawLength, 1, registry.MAX_METADATA_URI_BYTES());
        ChallengeRegistry.VersionInput memory input = _version(keccak256(abi.encode(rawLength)));
        input.metadataURI = new string(uriLength);

        vm.prank(registrar);
        uint256 challengeId = registry.createChallenge(controller, input);
        assertEq(bytes(registry.getVersion(challengeId, 1).metadataURI).length, uriLength);
    }

    function testFuzz_VersionHistoryPreservesEveryCommitment(uint8 rawCount, bytes32 seed) public {
        uint256 count = bound(rawCount, 1, 20);
        uint256 challengeId = _create();

        for (uint256 i = 0; i < count; i++) {
            bytes32 salt = keccak256(abi.encode(seed, i));
            ChallengeRegistry.VersionInput memory input = _version(salt);
            vm.prank(controller);
            uint32 version = registry.addVersion(challengeId, input);
            ChallengeRegistry.ChallengeVersion memory stored = registry.getVersion(challengeId, version);
            assertEq(stored.metadataHash, input.metadataHash);
            assertEq(stored.sealedArtifactCommitment, input.sealedArtifactCommitment);
            assertEq(stored.evaluatorCommitment, input.evaluatorCommitment);
            assertEq(stored.releasePolicyCommitment, input.releasePolicyCommitment);
        }

        assertEq(registry.getChallenge(challengeId).latestVersion, count + 1);
    }

    function testFuzz_ChallengeIdsAreMonotonic(uint8 rawCount) public {
        uint256 count = bound(rawCount, 1, 25);
        for (uint256 i = 1; i <= count; i++) {
            vm.prank(registrar);
            uint256 challengeId = registry.createChallenge(controller, _version(keccak256(abi.encode("challenge", i))));
            assertEq(challengeId, i);
        }
        assertEq(registry.challengeCount(), count);
        assertEq(registry.nextChallengeId(), count + 1);
    }
}
