// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {ConfigureChallengeRegistryReleaseScript} from "../script/ConfigureChallengeRegistryRelease.s.sol";
import {ChallengeRegistry} from "../src/ChallengeRegistry.sol";

contract ConfigureChallengeRegistryReleaseHarness is ConfigureChallengeRegistryReleaseScript {
    function executeConfiguredPhase(uint256 phase, ReleaseInputs memory inputs) external {
        _executePhase(phase, inputs);
    }

    function decodeAuthorityProjection(string memory json) external pure returns (ReleaseInputs memory) {
        return _decodeAuthorityProjection(json);
    }
}

contract ConfigureChallengeRegistryReleaseTest is Test {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    address internal operator;
    ChallengeRegistry internal registry;
    ConfigureChallengeRegistryReleaseHarness internal script;

    function setUp() public {
        vm.chainId(BASE_SEPOLIA_CHAIN_ID);
        operator = msg.sender;
        registry = new ChallengeRegistry(operator);
        script = new ConfigureChallengeRegistryReleaseHarness();
    }

    function test_TwoPhasesProduceExactReviewedGenesisCatalog() public {
        _runPhase(1);
        assertEq(registry.challengeCount(), 2);
        assertEq(registry.nextChallengeId(), 3);

        for (uint256 challengeId = 1; challengeId <= 2; ++challengeId) {
            ChallengeRegistry.Challenge memory challenge = registry.getChallenge(challengeId);
            assertEq(uint8(challenge.lifecycle), uint8(ChallengeRegistry.Lifecycle.Draft));
            assertEq(challenge.latestVersion, 1);
            assertFalse(challenge.configurationFrozen);
            assertEq(registry.reviewEligibleAt(challengeId), challenge.createdAt + registry.MIN_VERSION_REVIEW_DELAY());
        }

        uint64 latestReview = registry.reviewEligibleAt(2);
        vm.warp(latestReview);
        _runPhase(2);

        ConfigureChallengeRegistryReleaseScript.CatalogEntry[] memory catalog = _catalog();
        for (uint256 index = 0; index < catalog.length; ++index) {
            ChallengeRegistry.Challenge memory challenge = registry.getChallenge(index + 1);
            ChallengeRegistry.ChallengeVersion memory version = registry.getVersion(index + 1, 1);
            assertEq(challenge.controller, catalog[index].controller);
            assertEq(challenge.pendingController, address(0));
            assertEq(uint8(challenge.lifecycle), uint8(ChallengeRegistry.Lifecycle.Open));
            assertFalse(challenge.paused);
            assertTrue(challenge.configurationFrozen);
            assertEq(version.metadataURI, catalog[index].metadataURI);
            assertEq(version.metadataHash, catalog[index].metadataHash);
            assertEq(version.sealedArtifactCommitment, catalog[index].sealedArtifactCommitment);
            assertEq(version.evaluatorCommitment, catalog[index].evaluatorCommitment);
            assertEq(version.releasePolicyCommitment, catalog[index].releasePolicyCommitment);
        }
    }

    function test_CannotSkipReviewOrReplayEitherPhase() public {
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 challenge count"));
        _runPhase(2);

        _runPhase(1);
        vm.expectRevert(bytes("phase 1 requires the exact pristine ChallengeRegistry"));
        _runPhase(1);
        vm.expectRevert(bytes("challenge version review timelock has not elapsed"));
        _runPhase(2);

        vm.warp(registry.reviewEligibleAt(2));
        _runPhase(2);
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 challenge state"));
        _runPhase(2);
    }

    function test_ExtraChallengeOrVersionDriftFailsClosed() public {
        _runPhase(1);

        vm.prank(operator);
        registry.createChallenge(makeAddr("extra-controller"), _versionInput("extra"));
        vm.warp(registry.reviewEligibleAt(2));
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 challenge count"));
        _runPhase(2);

        vm.prank(operator);
        ChallengeRegistry cleanRegistry = new ChallengeRegistry(operator);
        registry = cleanRegistry;
        _runPhase(1);
        vm.prank(_catalog()[0].controller);
        registry.addVersion(1, _versionInput("unreviewed-v2"));
        vm.warp(registry.reviewEligibleAt(2));
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 challenge state"));
        _runPhase(2);
    }

    function test_PendingControllerPauseAndTimestampDriftFailClosed() public {
        _runPhase(1);
        ConfigureChallengeRegistryReleaseScript.CatalogEntry[] memory catalog = _catalog();

        vm.prank(catalog[0].controller);
        registry.transferChallengeController(1, makeAddr("pending-controller"));
        vm.warp(registry.reviewEligibleAt(2));
        vm.expectRevert(bytes("phase 2 requires the exact phase-1 challenge state"));
        _runPhase(2);

        vm.prank(operator);
        registry = new ChallengeRegistry(operator);
        _runPhase(1);
        vm.warp(block.timestamp + 1);
        vm.prank(catalog[0].controller);
        registry.setChallengePaused(1, true);
        vm.warp(block.timestamp + 1);
        vm.prank(catalog[0].controller);
        registry.setChallengePaused(1, false);
        vm.warp(registry.reviewEligibleAt(2));
        vm.expectRevert(bytes("phase-1 challenge timestamps show unreviewed mutation"));
        _runPhase(2);
    }

    function test_RuntimeOwnerChainAndCatalogPinsAreRequired() public {
        ConfigureChallengeRegistryReleaseScript.ReleaseInputs memory inputs = _inputs();
        inputs.registryRuntimeCodeHash = keccak256("wrong-runtime");
        vm.expectRevert(bytes("ChallengeRegistry runtime code hash mismatch"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.operator = makeAddr("wrong-owner");
        vm.expectRevert(bytes("operator does not own ChallengeRegistry"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.catalog[1].challengeId = 3;
        vm.expectRevert(bytes("Arena challenge IDs must be the contiguous range 1..N"));
        script.executeConfiguredPhase(1, inputs);

        inputs = _inputs();
        inputs.catalog[0].metadataHash = inputs.catalog[0].evaluatorCommitment;
        inputs.catalog[0].catalogManifestHash = inputs.catalog[0].metadataHash;
        vm.expectRevert(bytes("Arena commitments must be pairwise distinct"));
        script.executeConfiguredPhase(1, inputs);

        vm.chainId(1);
        vm.expectRevert(bytes("ChallengeRegistry release is Base Sepolia only"));
        script.executeConfiguredPhase(1, _inputs());
    }

    function test_DecodesCanonicalAuthorityProjectionWithoutOperatorFieldParsing() public view {
        ConfigureChallengeRegistryReleaseScript.ReleaseInputs memory inputs =
            script.decodeAuthorityProjection(_authorityProjectionJson());
        assertEq(address(inputs.registry), address(registry));
        assertEq(inputs.registryRuntimeCodeHash, address(registry).codehash);
        assertEq(inputs.operator, operator);
        assertEq(inputs.minimumVersionReviewDelay, registry.MIN_VERSION_REVIEW_DELAY());
        assertEq(inputs.catalog.length, 2);
        assertEq(inputs.catalog[0].challengeId, 1);
        assertEq(inputs.catalog[1].challengeId, 2);
        assertEq(inputs.catalog[1].metadataURI, "ipfs://arena/challenge-2");
    }

    function _runPhase(uint256 phase) internal {
        script.executeConfiguredPhase(phase, _inputs());
    }

    function _inputs() internal view returns (ConfigureChallengeRegistryReleaseScript.ReleaseInputs memory) {
        return ConfigureChallengeRegistryReleaseScript.ReleaseInputs({
            registry: registry,
            registryRuntimeCodeHash: address(registry).codehash,
            operator: operator,
            minimumVersionReviewDelay: 2 days,
            catalog: _catalog()
        });
    }

    function _catalog() internal pure returns (ConfigureChallengeRegistryReleaseScript.CatalogEntry[] memory catalog) {
        catalog = new ConfigureChallengeRegistryReleaseScript.CatalogEntry[](2);
        catalog[0] = _entry(1, address(0x1000000000000000000000000000000000000001));
        catalog[1] = _entry(2, address(0x1000000000000000000000000000000000000002));
    }

    function _entry(uint256 challengeId, address controller)
        internal
        pure
        returns (ConfigureChallengeRegistryReleaseScript.CatalogEntry memory)
    {
        return ConfigureChallengeRegistryReleaseScript.CatalogEntry({
            catalogKey: challengeId == 1 ? "bio-qc@1.0.0" : "protein-fold@1.0.0",
            challengeId: challengeId,
            version: 1,
            controller: controller,
            catalogManifestHash: keccak256(abi.encode("metadata", challengeId)),
            metadataURI: challengeId == 1 ? "ipfs://arena/challenge-1" : "ipfs://arena/challenge-2",
            metadataHash: keccak256(abi.encode("metadata", challengeId)),
            sealedArtifactCommitment: keccak256(abi.encode("sealed", challengeId)),
            evaluatorCommitment: keccak256(abi.encode("evaluator", challengeId)),
            releasePolicyCommitment: keccak256(abi.encode("release", challengeId))
        });
    }

    function _versionInput(string memory label) internal pure returns (ChallengeRegistry.VersionInput memory) {
        return ChallengeRegistry.VersionInput({
            metadataURI: string.concat("ipfs://", label),
            metadataHash: keccak256(abi.encode("metadata", label)),
            sealedArtifactCommitment: keccak256(abi.encode("sealed", label)),
            evaluatorCommitment: keccak256(abi.encode("evaluator", label)),
            releasePolicyCommitment: keccak256(abi.encode("release", label))
        });
    }

    function _authorityProjectionJson() internal view returns (string memory) {
        ConfigureChallengeRegistryReleaseScript.CatalogEntry[] memory catalog = _catalog();
        return string.concat(
            '{"schema":"dnai.challenge-registry-authority-projection.v1","releaseSha":"',
            "0123456789abcdef0123456789abcdef01234567",
            '","chainId":84532,"finalAuthoritySha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111',
            '","registry":{"address":"',
            vm.toString(address(registry)),
            '","runtimeCodeHash":"',
            vm.toString(address(registry).codehash),
            '","owner":"',
            vm.toString(operator),
            '","pendingOwner":"0x0000000000000000000000000000000000000000","registryPaused":false,"minimumVersionReviewDelaySeconds":172800,"expectedChallengeCount":2},"entries":[',
            _entryJson(catalog[0]),
            ",",
            _entryJson(catalog[1]),
            "]}"
        );
    }

    function _entryJson(ConfigureChallengeRegistryReleaseScript.CatalogEntry memory entry)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            '{"catalogKey":"',
            entry.catalogKey,
            '","challengeId":',
            vm.toString(entry.challengeId),
            ',"version":1,"controller":"',
            vm.toString(entry.controller),
            '","pendingController":"0x0000000000000000000000000000000000000000","lifecycle":"open","paused":false,"configurationFrozen":true,"catalogManifestHash":"',
            vm.toString(entry.metadataHash),
            '","metadataURI":"',
            entry.metadataURI,
            '","metadataHash":"',
            vm.toString(entry.metadataHash),
            '","sealedArtifactCommitment":"',
            vm.toString(entry.sealedArtifactCommitment),
            '","evaluatorCommitment":"',
            vm.toString(entry.evaluatorCommitment),
            '","releasePolicyCommitment":"',
            vm.toString(entry.releasePolicyCommitment),
            '"}'
        );
    }
}
