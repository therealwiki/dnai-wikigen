// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ChallengeRegistry - non-custodial challenge metadata and commitment registry
/// @notice Records versioned public metadata references and commitments for sealed
///         evaluation challenges. This contract deliberately has no prize, bond,
///         escrow, token, submission, or payout functionality. Private challenge
///         material must remain outside the chain; only commitments belong here.
contract ChallengeRegistry {
    uint256 public constant MAX_METADATA_URI_BYTES = 256;
    uint64 public constant MIN_VERSION_REVIEW_DELAY = 2 days;

    enum Lifecycle {
        Draft,
        Open,
        Closed,
        Cancelled,
        Archived
    }

    struct Challenge {
        address controller;
        address pendingController;
        Lifecycle lifecycle;
        uint64 createdAt;
        uint64 updatedAt;
        uint32 latestVersion;
        bool paused;
        bool configurationFrozen;
    }

    struct VersionInput {
        string metadataURI;
        bytes32 metadataHash;
        bytes32 sealedArtifactCommitment;
        bytes32 evaluatorCommitment;
        bytes32 releasePolicyCommitment;
    }

    struct ChallengeVersion {
        string metadataURI;
        bytes32 metadataHash;
        bytes32 sealedArtifactCommitment;
        bytes32 evaluatorCommitment;
        bytes32 releasePolicyCommitment;
        uint64 createdAt;
    }

    address public owner;
    address public pendingOwner;
    bool public registryPaused;
    uint256 public nextChallengeId = 1;

    mapping(address => bool) public registrars;
    mapping(uint256 => bool) public controllerChallengePaused;
    mapping(uint256 => bool) public governanceChallengePaused;
    /// @notice Earliest timestamp at which the current latest version may be
    ///         frozen. Adding a version always replaces this timestamp.
    mapping(uint256 => uint64) public reviewEligibleAt;
    mapping(uint256 => Challenge) private _challenges;
    mapping(uint256 => mapping(uint32 => ChallengeVersion)) private _versions;

    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RegistrarSet(address indexed registrar, bool allowed);
    event RegistryPauseSet(bool paused);
    event ChallengeCreated(uint256 indexed challengeId, address indexed controller, uint32 initialVersion);
    event ChallengeVersionAdded(
        uint256 indexed challengeId,
        uint32 indexed version,
        bytes32 metadataHash,
        bytes32 sealedArtifactCommitment,
        bytes32 evaluatorCommitment,
        bytes32 releasePolicyCommitment,
        string metadataURI
    );
    event ChallengeLifecycleChanged(uint256 indexed challengeId, Lifecycle previousLifecycle, Lifecycle newLifecycle);
    event ChallengeControllerPauseSet(uint256 indexed challengeId, address indexed controller, bool paused);
    event ChallengeGovernancePauseSet(uint256 indexed challengeId, address indexed governance, bool paused);
    /// @dev Emitted only when the effective pause state changes. Source-specific
    ///      events above are emitted even when the other pause source keeps the
    ///      challenge effectively paused.
    event ChallengePauseSet(uint256 indexed challengeId, bool paused);
    event ChallengeConfigurationFrozen(uint256 indexed challengeId, uint32 finalVersion);
    event ChallengeReviewScheduled(uint256 indexed challengeId, uint32 indexed version, uint64 eligibleAt);
    event ChallengeControllerTransferStarted(
        uint256 indexed challengeId, address indexed currentController, address indexed pendingController
    );
    event ChallengeControllerTransferCancelled(uint256 indexed challengeId, address indexed pendingController);
    event ChallengeControllerTransferred(
        uint256 indexed challengeId, address indexed previousController, address indexed newController
    );

    error NotOwner();
    error NotPendingOwner();
    error NotRegistrar();
    error NotChallengeController();
    error ZeroAddress();
    error SelfAddress();
    error ZeroCommitment();
    error EmptyMetadataURI();
    error MetadataURITooLong();
    error ChallengeNotFound();
    error VersionNotFound();
    error RegistryPaused();
    error ChallengePaused();
    error ChallengeConfigurationFrozenError();
    error ChallengeConfigurationNotFrozen();
    error ChallengeReviewPending(uint64 eligibleAt);
    error InvalidLifecycleForOperation();
    error InvalidLifecycleTransition(Lifecycle current, Lifecycle requested);
    error NoPendingController();
    error NoStateChange();
    error NoCustody();

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (initialOwner == address(this)) revert SelfAddress();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    modifier onlyRegistrar() {
        _checkRegistrar();
        _;
    }

    modifier whenRegistryActive() {
        _checkRegistryActive();
        _;
    }

    function _checkOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _checkRegistrar() internal view {
        if (msg.sender != owner && !registrars[msg.sender]) revert NotRegistrar();
    }

    function _checkRegistryActive() internal view {
        if (registryPaused) revert RegistryPaused();
    }

    /// @notice Begin a two-step registry ownership transfer.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == address(this)) revert SelfAddress();
        if (newOwner == owner || newOwner == pendingOwner) revert NoStateChange();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Accept registry ownership from the proposed account.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Grant or revoke permission to create new challenge records.
    /// @dev Revocation remains available during a global pause.
    function setRegistrar(address registrar, bool allowed) external onlyOwner {
        if (registrar == address(0)) revert ZeroAddress();
        if (registrars[registrar] == allowed) revert NoStateChange();
        if (registryPaused && allowed) revert RegistryPaused();
        registrars[registrar] = allowed;
        emit RegistrarSet(registrar, allowed);
    }

    /// @notice Emergency stop for challenge creation, versioning, controller
    ///         transfer, lifecycle changes, and unpausing individual challenges.
    /// @dev Safety-reducing operations such as registrar revocation, individual
    ///      challenge pause, and configuration freeze remain available.
    function setRegistryPaused(bool paused) external onlyOwner {
        if (registryPaused == paused) revert NoStateChange();
        registryPaused = paused;
        emit RegistryPauseSet(paused);
    }

    /// @notice Create a Draft challenge with immutable version 1.
    function createChallenge(address controller, VersionInput calldata initialVersion)
        external
        onlyRegistrar
        whenRegistryActive
        returns (uint256 challengeId)
    {
        if (controller == address(0)) revert ZeroAddress();
        if (controller == address(this)) revert SelfAddress();
        _validateVersionInput(initialVersion);

        challengeId = nextChallengeId++;
        uint64 timestamp = uint64(block.timestamp);
        Challenge storage challenge = _challenges[challengeId];
        challenge.controller = controller;
        challenge.lifecycle = Lifecycle.Draft;
        challenge.createdAt = timestamp;
        challenge.updatedAt = timestamp;

        uint32 initialVersionNumber = _addVersion(challengeId, challenge, initialVersion);
        emit ChallengeCreated(challengeId, controller, initialVersionNumber);
    }

    /// @notice Add an immutable configuration version while the challenge is Draft.
    function addVersion(uint256 challengeId, VersionInput calldata versionInput)
        external
        whenRegistryActive
        returns (uint32 version)
    {
        Challenge storage challenge = _getChallenge(challengeId);
        _checkChallengeController(challenge);
        _requireChallengeActive(challenge);
        if (challenge.configurationFrozen) revert ChallengeConfigurationFrozenError();
        if (challenge.lifecycle != Lifecycle.Draft) revert InvalidLifecycleForOperation();
        _validateVersionInput(versionInput);

        version = _addVersion(challengeId, challenge, versionInput);
    }

    /// @notice Permanently freeze metadata, commitments, and controller authority
    ///         for a Draft challenge. Lifecycle and emergency pause remain usable.
    function freezeChallengeConfiguration(uint256 challengeId) external {
        Challenge storage challenge = _getChallenge(challengeId);
        _checkChallengeController(challenge);
        if (challenge.configurationFrozen) revert ChallengeConfigurationFrozenError();
        if (challenge.lifecycle != Lifecycle.Draft) revert InvalidLifecycleForOperation();
        uint64 eligibleAt = reviewEligibleAt[challengeId];
        if (block.timestamp < eligibleAt) revert ChallengeReviewPending(eligibleAt);

        address proposedController = challenge.pendingController;
        if (proposedController != address(0)) {
            challenge.pendingController = address(0);
            emit ChallengeControllerTransferCancelled(challengeId, proposedController);
        }
        challenge.configurationFrozen = true;
        challenge.updatedAt = uint64(block.timestamp);
        emit ChallengeConfigurationFrozen(challengeId, challenge.latestVersion);
    }

    /// @notice Apply a forward-only lifecycle transition.
    /// @dev Opening requires the final challenge configuration to be frozen.
    function setLifecycle(uint256 challengeId, Lifecycle requested) external whenRegistryActive {
        Challenge storage challenge = _getChallenge(challengeId);
        _checkChallengeController(challenge);
        _requireChallengeActive(challenge);

        Lifecycle current = challenge.lifecycle;
        if (requested == current) revert NoStateChange();
        if (requested == Lifecycle.Open && !challenge.configurationFrozen) {
            revert ChallengeConfigurationNotFrozen();
        }
        if (!_validTransition(current, requested)) {
            revert InvalidLifecycleTransition(current, requested);
        }

        challenge.lifecycle = requested;
        challenge.updatedAt = uint64(block.timestamp);
        emit ChallengeLifecycleChanged(challengeId, current, requested);
    }

    /// @notice Set the caller's independent pause source for a Draft/Open challenge.
    /// @dev The owner controls the governance emergency pause; the controller
    ///      controls only the controller pause. A controller can never clear a
    ///      governance pause. `Challenge.paused` remains the effective OR-state
    ///      for ABI compatibility with release verifiers. Pausing remains
    ///      available while the registry is paused; unpausing does not.
    function setChallengePaused(uint256 challengeId, bool paused) external {
        Challenge storage challenge = _getChallenge(challengeId);
        _checkChallengeController(challenge);
        if (challenge.lifecycle != Lifecycle.Draft && challenge.lifecycle != Lifecycle.Open) {
            revert InvalidLifecycleForOperation();
        }
        if (!paused && registryPaused) revert RegistryPaused();

        bool wasEffectivelyPaused = challenge.paused;
        if (msg.sender == owner) {
            if (governanceChallengePaused[challengeId] == paused) revert NoStateChange();
            governanceChallengePaused[challengeId] = paused;
            emit ChallengeGovernancePauseSet(challengeId, msg.sender, paused);
        } else {
            if (controllerChallengePaused[challengeId] == paused) revert NoStateChange();
            controllerChallengePaused[challengeId] = paused;
            emit ChallengeControllerPauseSet(challengeId, msg.sender, paused);
        }

        bool isEffectivelyPaused = controllerChallengePaused[challengeId] || governanceChallengePaused[challengeId];
        challenge.paused = isEffectivelyPaused;
        challenge.updatedAt = uint64(block.timestamp);
        if (wasEffectivelyPaused != isEffectivelyPaused) {
            emit ChallengePauseSet(challengeId, isEffectivelyPaused);
        }
    }

    /// @notice Begin a two-step controller transfer while configuration is mutable.
    function transferChallengeController(uint256 challengeId, address newController) external whenRegistryActive {
        if (newController == address(0)) revert ZeroAddress();
        if (newController == address(this)) revert SelfAddress();
        Challenge storage challenge = _getChallenge(challengeId);
        _checkChallengeController(challenge);
        _requireChallengeActive(challenge);
        if (challenge.configurationFrozen) revert ChallengeConfigurationFrozenError();
        if (challenge.lifecycle != Lifecycle.Draft) revert InvalidLifecycleForOperation();
        if (newController == challenge.controller || newController == challenge.pendingController) {
            revert NoStateChange();
        }

        challenge.pendingController = newController;
        challenge.updatedAt = uint64(block.timestamp);
        emit ChallengeControllerTransferStarted(challengeId, challenge.controller, newController);
    }

    /// @notice Accept challenge control from the proposed account.
    function acceptChallengeController(uint256 challengeId) external whenRegistryActive {
        Challenge storage challenge = _getChallenge(challengeId);
        _requireChallengeActive(challenge);
        if (challenge.configurationFrozen) revert ChallengeConfigurationFrozenError();
        if (challenge.lifecycle != Lifecycle.Draft) revert InvalidLifecycleForOperation();
        if (challenge.pendingController == address(0)) revert NoPendingController();
        if (msg.sender != challenge.pendingController) revert NotChallengeController();

        address previousController = challenge.controller;
        challenge.controller = msg.sender;
        challenge.pendingController = address(0);
        challenge.updatedAt = uint64(block.timestamp);
        emit ChallengeControllerTransferred(challengeId, previousController, msg.sender);
    }

    /// @notice Cancel a pending challenge-controller transfer.
    function cancelChallengeControllerTransfer(uint256 challengeId) external {
        Challenge storage challenge = _getChallenge(challengeId);
        _checkChallengeController(challenge);
        address proposedController = challenge.pendingController;
        if (proposedController == address(0)) revert NoPendingController();
        challenge.pendingController = address(0);
        challenge.updatedAt = uint64(block.timestamp);
        emit ChallengeControllerTransferCancelled(challengeId, proposedController);
    }

    function getChallenge(uint256 challengeId) external view returns (Challenge memory) {
        Challenge storage challenge = _getChallenge(challengeId);
        return challenge;
    }

    function getVersion(uint256 challengeId, uint32 version) external view returns (ChallengeVersion memory) {
        Challenge storage challenge = _getChallenge(challengeId);
        if (version == 0 || version > challenge.latestVersion) revert VersionNotFound();
        return _versions[challengeId][version];
    }

    function latestVersion(uint256 challengeId) external view returns (ChallengeVersion memory) {
        Challenge storage challenge = _getChallenge(challengeId);
        return _versions[challengeId][challenge.latestVersion];
    }

    function challengeExists(uint256 challengeId) external view returns (bool) {
        return _challenges[challengeId].controller != address(0);
    }

    function challengeCount() external view returns (uint256) {
        return nextChallengeId - 1;
    }

    function _addVersion(uint256 challengeId, Challenge storage challenge, VersionInput calldata versionInput)
        internal
        returns (uint32 version)
    {
        version = challenge.latestVersion + 1;
        challenge.latestVersion = version;
        challenge.updatedAt = uint64(block.timestamp);
        _versions[challengeId][version] = ChallengeVersion({
            metadataURI: versionInput.metadataURI,
            metadataHash: versionInput.metadataHash,
            sealedArtifactCommitment: versionInput.sealedArtifactCommitment,
            evaluatorCommitment: versionInput.evaluatorCommitment,
            releasePolicyCommitment: versionInput.releasePolicyCommitment,
            createdAt: uint64(block.timestamp)
        });
        uint64 eligibleAt = uint64(block.timestamp) + MIN_VERSION_REVIEW_DELAY;
        reviewEligibleAt[challengeId] = eligibleAt;

        emit ChallengeVersionAdded(
            challengeId,
            version,
            versionInput.metadataHash,
            versionInput.sealedArtifactCommitment,
            versionInput.evaluatorCommitment,
            versionInput.releasePolicyCommitment,
            versionInput.metadataURI
        );
        emit ChallengeReviewScheduled(challengeId, version, eligibleAt);
    }

    function _validateVersionInput(VersionInput calldata versionInput) internal pure {
        uint256 uriLength = bytes(versionInput.metadataURI).length;
        if (uriLength == 0) revert EmptyMetadataURI();
        if (uriLength > MAX_METADATA_URI_BYTES) revert MetadataURITooLong();
        if (
            versionInput.metadataHash == bytes32(0) || versionInput.sealedArtifactCommitment == bytes32(0)
                || versionInput.evaluatorCommitment == bytes32(0) || versionInput.releasePolicyCommitment == bytes32(0)
        ) revert ZeroCommitment();
    }

    function _getChallenge(uint256 challengeId) internal view returns (Challenge storage challenge) {
        challenge = _challenges[challengeId];
        if (challenge.controller == address(0)) revert ChallengeNotFound();
    }

    function _checkChallengeController(Challenge storage challenge) internal view {
        if (msg.sender != owner && msg.sender != challenge.controller) {
            revert NotChallengeController();
        }
    }

    function _requireChallengeActive(Challenge storage challenge) internal view {
        if (challenge.paused) revert ChallengePaused();
    }

    function _validTransition(Lifecycle current, Lifecycle requested) internal pure returns (bool) {
        if (current == Lifecycle.Draft) {
            return requested == Lifecycle.Open || requested == Lifecycle.Cancelled;
        }
        if (current == Lifecycle.Open) {
            return requested == Lifecycle.Closed || requested == Lifecycle.Cancelled;
        }
        if (current == Lifecycle.Closed || current == Lifecycle.Cancelled) {
            return requested == Lifecycle.Archived;
        }
        return false;
    }

    receive() external payable {
        revert NoCustody();
    }

    fallback() external payable {
        revert NoCustody();
    }
}
