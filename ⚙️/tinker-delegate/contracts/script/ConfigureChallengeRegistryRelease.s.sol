// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {ChallengeRegistry} from "../src/ChallengeRegistry.sol";

/// @notice Two-phase realization of the exact final-authority Arena genesis catalog.
/// @dev Phase 1 requires the pristine fresh registry and creates version 1 for
///      every contiguous challenge ID. Phase 2 runs only after every version's
///      fixed two-day review delay, freezes each configuration, and opens it.
///      The variable-length catalog is emitted by the canonical final-authority
///      projector; this script never accepts individually operator-authored
///      challenge fields.
contract ConfigureChallengeRegistryReleaseScript is Script {
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 internal constant MAX_GENESIS_CHALLENGES = 32;
    bytes32 internal constant PROJECTION_SCHEMA_HASH = keccak256("dnai.challenge-registry-authority-projection.v1");

    struct CatalogEntry {
        string catalogKey;
        uint256 challengeId;
        uint32 version;
        address controller;
        bytes32 catalogManifestHash;
        string metadataURI;
        bytes32 metadataHash;
        bytes32 sealedArtifactCommitment;
        bytes32 evaluatorCommitment;
        bytes32 releasePolicyCommitment;
    }

    struct ReleaseInputs {
        ChallengeRegistry registry;
        bytes32 registryRuntimeCodeHash;
        address operator;
        uint64 minimumVersionReviewDelay;
        CatalogEntry[] catalog;
    }

    function run() public {
        _executePhase(
            vm.envUint("CHALLENGE_REGISTRY_RELEASE_PHASE"),
            _decodeAuthorityProjection(vm.envString("CHALLENGE_REGISTRY_RELEASE_CATALOG_JSON"))
        );
    }

    function runPhase(uint256 phase, string memory authorityProjectionJson) public {
        _executePhase(phase, _decodeAuthorityProjection(authorityProjectionJson));
    }

    function _decodeAuthorityProjection(string memory json) internal pure returns (ReleaseInputs memory inputs) {
        require(
            keccak256(bytes(vm.parseJsonString(json, ".schema"))) == PROJECTION_SCHEMA_HASH,
            "ChallengeRegistry authority projection schema mismatch"
        );
        require(
            vm.parseJsonUint(json, ".chainId") == BASE_SEPOLIA_CHAIN_ID,
            "ChallengeRegistry authority projection chain mismatch"
        );
        uint256 count = vm.parseJsonUint(json, ".registry.expectedChallengeCount");
        require(count > 0 && count <= MAX_GENESIS_CHALLENGES, "invalid ChallengeRegistry genesis catalog size");

        inputs.registry = ChallengeRegistry(payable(vm.parseJsonAddress(json, ".registry.address")));
        inputs.registryRuntimeCodeHash = vm.parseJsonBytes32(json, ".registry.runtimeCodeHash");
        inputs.operator = vm.parseJsonAddress(json, ".registry.owner");
        require(
            vm.parseJsonAddress(json, ".registry.pendingOwner") == address(0),
            "reviewed ChallengeRegistry pending owner must be zero"
        );
        require(!vm.parseJsonBool(json, ".registry.registryPaused"), "reviewed ChallengeRegistry must be active");
        uint256 reviewDelay = vm.parseJsonUint(json, ".registry.minimumVersionReviewDelaySeconds");
        require(reviewDelay <= type(uint64).max, "ChallengeRegistry review delay does not fit uint64");
        // The explicit upper-bound check above proves that this uint64 conversion cannot truncate.
        // forge-lint: disable-next-line(unsafe-typecast)
        inputs.minimumVersionReviewDelay = uint64(reviewDelay);
        inputs.catalog = new CatalogEntry[](count);

        for (uint256 index = 0; index < count; ++index) {
            string memory prefix = string.concat(".entries[", vm.toString(index), "]");
            require(
                vm.parseJsonAddress(json, string.concat(prefix, ".pendingController")) == address(0),
                "reviewed challenge pending controller must be zero"
            );
            require(
                keccak256(bytes(vm.parseJsonString(json, string.concat(prefix, ".lifecycle")))) == keccak256("open"),
                "reviewed challenge lifecycle must be open"
            );
            require(
                !vm.parseJsonBool(json, string.concat(prefix, ".paused"))
                    && vm.parseJsonBool(json, string.concat(prefix, ".configurationFrozen")),
                "reviewed challenge must be unpaused and configuration-frozen"
            );
            uint256 version = vm.parseJsonUint(json, string.concat(prefix, ".version"));
            require(version == 1, "Arena genesis catalog must use version 1");
            // The exact version-one check above proves that this uint32 conversion cannot truncate.
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 exactVersion = uint32(version);
            inputs.catalog[index] = CatalogEntry({
                catalogKey: vm.parseJsonString(json, string.concat(prefix, ".catalogKey")),
                challengeId: vm.parseJsonUint(json, string.concat(prefix, ".challengeId")),
                version: exactVersion,
                controller: vm.parseJsonAddress(json, string.concat(prefix, ".controller")),
                catalogManifestHash: vm.parseJsonBytes32(json, string.concat(prefix, ".catalogManifestHash")),
                metadataURI: vm.parseJsonString(json, string.concat(prefix, ".metadataURI")),
                metadataHash: vm.parseJsonBytes32(json, string.concat(prefix, ".metadataHash")),
                sealedArtifactCommitment: vm.parseJsonBytes32(json, string.concat(prefix, ".sealedArtifactCommitment")),
                evaluatorCommitment: vm.parseJsonBytes32(json, string.concat(prefix, ".evaluatorCommitment")),
                releasePolicyCommitment: vm.parseJsonBytes32(json, string.concat(prefix, ".releasePolicyCommitment"))
            });
        }
    }

    function _executePhase(uint256 phase, ReleaseInputs memory inputs) internal {
        require(block.chainid == BASE_SEPOLIA_CHAIN_ID, "ChallengeRegistry release is Base Sepolia only");
        _requireCommonReleaseInputs(inputs);

        if (phase == 1) _phaseOne(inputs);
        else if (phase == 2) _phaseTwo(inputs);
        else revert("CHALLENGE_REGISTRY_RELEASE_PHASE must be 1 or 2");

        console.log("ChallengeRegistry release phase:", phase);
        console.log("ChallengeRegistry:", address(inputs.registry));
        console.log("Genesis challenge count:", inputs.registry.challengeCount());
    }

    function _requireCommonReleaseInputs(ReleaseInputs memory inputs) internal view {
        ChallengeRegistry registry = inputs.registry;
        require(
            inputs.registryRuntimeCodeHash != bytes32(0)
                && address(registry).codehash == inputs.registryRuntimeCodeHash,
            "ChallengeRegistry runtime code hash mismatch"
        );
        require(
            inputs.operator != address(0) && registry.owner() == inputs.operator,
            "operator does not own ChallengeRegistry"
        );
        require(registry.pendingOwner() == address(0), "ChallengeRegistry has a pending owner");
        require(!registry.registryPaused(), "ChallengeRegistry must remain active");
        require(
            inputs.minimumVersionReviewDelay == registry.MIN_VERSION_REVIEW_DELAY(),
            "ChallengeRegistry review delay mismatch"
        );
        require(
            inputs.catalog.length > 0 && inputs.catalog.length <= MAX_GENESIS_CHALLENGES,
            "invalid ChallengeRegistry genesis catalog size"
        );

        for (uint256 index = 0; index < inputs.catalog.length; ++index) {
            CatalogEntry memory entry = inputs.catalog[index];
            require(bytes(entry.catalogKey).length > 0, "Arena catalog key must be nonempty");
            require(entry.challengeId == index + 1, "Arena challenge IDs must be the contiguous range 1..N");
            require(entry.version == 1, "Arena genesis catalog must use version 1");
            require(
                entry.controller != address(0) && entry.controller != address(registry),
                "Arena challenge controller is invalid"
            );
            uint256 uriLength = bytes(entry.metadataURI).length;
            require(
                uriLength > 0 && uriLength <= registry.MAX_METADATA_URI_BYTES(), "Arena metadata URI length is invalid"
            );
            require(
                entry.metadataHash != bytes32(0) && entry.sealedArtifactCommitment != bytes32(0)
                    && entry.evaluatorCommitment != bytes32(0) && entry.releasePolicyCommitment != bytes32(0),
                "Arena commitments must be nonzero"
            );
            require(
                entry.catalogManifestHash == entry.metadataHash,
                "Arena metadata hash must commit to the catalog manifest"
            );
            require(
                entry.metadataHash != entry.sealedArtifactCommitment && entry.metadataHash != entry.evaluatorCommitment
                    && entry.metadataHash != entry.releasePolicyCommitment
                    && entry.sealedArtifactCommitment != entry.evaluatorCommitment
                    && entry.sealedArtifactCommitment != entry.releasePolicyCommitment
                    && entry.evaluatorCommitment != entry.releasePolicyCommitment,
                "Arena commitments must be pairwise distinct"
            );
        }
    }

    function _phaseOne(ReleaseInputs memory inputs) internal {
        ChallengeRegistry registry = inputs.registry;
        require(
            registry.nextChallengeId() == 1 && registry.challengeCount() == 0,
            "phase 1 requires the exact pristine ChallengeRegistry"
        );

        vm.startBroadcast();
        for (uint256 index = 0; index < inputs.catalog.length; ++index) {
            CatalogEntry memory entry = inputs.catalog[index];
            uint256 challengeId = registry.createChallenge(
                entry.controller,
                ChallengeRegistry.VersionInput({
                    metadataURI: entry.metadataURI,
                    metadataHash: entry.metadataHash,
                    sealedArtifactCommitment: entry.sealedArtifactCommitment,
                    evaluatorCommitment: entry.evaluatorCommitment,
                    releasePolicyCommitment: entry.releasePolicyCommitment
                })
            );
            require(challengeId == entry.challengeId, "ChallengeRegistry assigned an unexpected genesis ID");
        }
        vm.stopBroadcast();

        _requireExactPhaseOneState(inputs, false);
    }

    function _phaseTwo(ReleaseInputs memory inputs) internal {
        _requireExactPhaseOneState(inputs, true);

        vm.startBroadcast();
        for (uint256 index = 0; index < inputs.catalog.length; ++index) {
            uint256 challengeId = inputs.catalog[index].challengeId;
            inputs.registry.freezeChallengeConfiguration(challengeId);
            inputs.registry.setLifecycle(challengeId, ChallengeRegistry.Lifecycle.Open);
        }
        vm.stopBroadcast();

        _requireExactFinalState(inputs);
    }

    function _requireExactPhaseOneState(ReleaseInputs memory inputs, bool reviewMustHaveElapsed) internal view {
        ChallengeRegistry registry = inputs.registry;
        require(
            registry.challengeCount() == inputs.catalog.length
                && registry.nextChallengeId() == inputs.catalog.length + 1,
            "phase 2 requires the exact phase-1 challenge count"
        );
        for (uint256 index = 0; index < inputs.catalog.length; ++index) {
            CatalogEntry memory entry = inputs.catalog[index];
            ChallengeRegistry.Challenge memory challenge = registry.getChallenge(entry.challengeId);
            require(
                challenge.controller == entry.controller && challenge.pendingController == address(0)
                    && challenge.lifecycle == ChallengeRegistry.Lifecycle.Draft && challenge.latestVersion == 1
                    && !challenge.paused && !challenge.configurationFrozen
                    && !registry.controllerChallengePaused(entry.challengeId)
                    && !registry.governanceChallengePaused(entry.challengeId),
                "phase 2 requires the exact phase-1 challenge state"
            );
            require(
                challenge.createdAt != 0 && challenge.updatedAt == challenge.createdAt,
                "phase-1 challenge timestamps show unreviewed mutation"
            );
            uint64 eligibleAt = registry.reviewEligibleAt(entry.challengeId);
            require(
                eligibleAt == challenge.createdAt + inputs.minimumVersionReviewDelay,
                "challenge review timestamp mismatch"
            );
            if (reviewMustHaveElapsed) {
                require(eligibleAt <= block.timestamp, "challenge version review timelock has not elapsed");
            }
            _requireExactVersion(registry, entry);
        }
    }

    function _requireExactFinalState(ReleaseInputs memory inputs) internal view {
        ChallengeRegistry registry = inputs.registry;
        require(
            registry.challengeCount() == inputs.catalog.length
                && registry.nextChallengeId() == inputs.catalog.length + 1,
            "final ChallengeRegistry challenge count mismatch"
        );
        for (uint256 index = 0; index < inputs.catalog.length; ++index) {
            CatalogEntry memory entry = inputs.catalog[index];
            ChallengeRegistry.Challenge memory challenge = registry.getChallenge(entry.challengeId);
            require(
                challenge.controller == entry.controller && challenge.pendingController == address(0)
                    && challenge.lifecycle == ChallengeRegistry.Lifecycle.Open && challenge.latestVersion == 1
                    && !challenge.paused && challenge.configurationFrozen
                    && !registry.controllerChallengePaused(entry.challengeId)
                    && !registry.governanceChallengePaused(entry.challengeId),
                "final challenge state does not match the reviewed Arena catalog"
            );
            require(
                challenge.createdAt != 0
                    && registry.reviewEligibleAt(entry.challengeId)
                        == challenge.createdAt + inputs.minimumVersionReviewDelay
                    && challenge.updatedAt >= registry.reviewEligibleAt(entry.challengeId),
                "final challenge timestamps do not preserve the reviewed version window"
            );
            _requireExactVersion(registry, entry);
        }
    }

    function _requireExactVersion(ChallengeRegistry registry, CatalogEntry memory entry) internal view {
        ChallengeRegistry.ChallengeVersion memory version = registry.getVersion(entry.challengeId, entry.version);
        require(
            keccak256(bytes(version.metadataURI)) == keccak256(bytes(entry.metadataURI))
                && version.metadataHash == entry.metadataHash
                && version.sealedArtifactCommitment == entry.sealedArtifactCommitment
                && version.evaluatorCommitment == entry.evaluatorCommitment
                && version.releasePolicyCommitment == entry.releasePolicyCommitment && version.createdAt != 0,
            "challenge version does not match the reviewed Arena catalog"
        );
    }
}
