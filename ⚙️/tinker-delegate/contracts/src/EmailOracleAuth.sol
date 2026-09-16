// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAppAuth, IERC165} from "./interfaces/IAppAuth.sol";

interface IDstackKmsRead {
    function registeredApps(address appId) external view returns (bool);

    function isAppAllowed(IAppAuth.AppBootInfo calldata bootInfo)
        external
        view
        returns (bool isAllowed, string memory reason);
}

/// @title EmailOracleAuth
/// @notice dstack-compatible boot and consumer authorization for the email oracle.
/// @dev A production release is deliberately more constrained than a mutable
///      development policy: exactly one compose, device, manager, and consumer
///      policy must be bound before the final freezes can close additions.
///      Emergency removals remain available after freezing and are monotonic.
contract EmailOracleAuth is IAppAuth {
    error NotOwner();
    error NotPendingOwner();
    error NotOwnerOrConsumerManager();
    error InvalidUpgradeDelay();
    error ZeroAddress();
    error ZeroHash();
    error RoleCollision();
    error OracleCodeFrozen();
    error ConsumerRegistryFrozen();
    error ConsumerManagerAdditionsFrozen();
    error KmsBindingFrozen();
    error ReleaseConfigurationIncomplete();
    error RuntimeCodeHashMismatch();
    error KmsRegistrationMissing();
    error KmsBootAuthorizationDenied();
    error RegistrationBlockUnavailable();
    error AlreadyAllowed();
    error NotAllowed();
    error AlreadyPending();
    error NotPending();
    error ActivationTooEarly(uint256 activatesAt);

    event OwnershipTransferStarted(address indexed previousOwner, address indexed pendingOwner);
    event OwnershipTransferCancelled(address indexed owner, address indexed cancelledPendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ConsumerManagerSet(address indexed account, bool allowed);
    event ConsumerManagerAdditionsFrozenForever(address indexed releaseManager);

    event OracleComposeHashProposed(bytes32 indexed composeHash, uint256 activatesAt);
    event OracleComposeHashActivated(bytes32 indexed composeHash);
    event OracleComposeHashProposalCancelled(bytes32 indexed composeHash);
    event OracleComposeHashRemoved(bytes32 indexed composeHash);

    event DeviceAdded(bytes32 indexed deviceId);
    event DeviceRemoved(bytes32 indexed deviceId);
    event AllowAnyDeviceSet(bool allowAnyDevice);

    event ConsumerComposeHashAdded(address indexed consumerAppId, bytes32 indexed composeHash);
    event ConsumerComposeHashRemoved(address indexed consumerAppId, bytes32 indexed composeHash);

    event OracleCodeAuthFrozen(bytes32 indexed releaseComposeHash, bytes32 indexed releaseDeviceId);
    event ConsumerRegistryFrozenForever(address indexed releaseConsumerAppId, bytes32 indexed releaseComposeHash);

    event KmsBindingProposed(
        address indexed kmsContract,
        address indexed kmsImplementation,
        bytes32 indexed registrationTxHash,
        uint256 activatesAt,
        bytes32 targetBootInfoHash,
        bytes32 restartKeyDerivationProofHash
    );
    event KmsBindingProposalCancelled(address indexed kmsContract, bytes32 indexed registrationTxHash);
    event KmsBindingActivatedAndFrozen(
        address indexed kmsContract,
        address indexed kmsImplementation,
        bytes32 indexed registrationTxHash,
        uint64 registrationBlock,
        bytes32 targetBootInfoHash,
        bytes32 restartKeyDerivationProofHash
    );

    event ConsumerEmergencyRevoked(address indexed consumerAppId);
    event ConsumerEmergencyRestored(address indexed consumerAppId);

    /// @dev Hashed OTP-delivery audit record for dispute resolution. `deliveryHash`
    /// is an off-chain commitment to the delivery context (consumer, request id,
    /// OTP hash) — never the raw OTP. `sequence` is the per-consumer ordinal so
    /// gaps/duplicates are detectable.
    event OtpDeliveryRecorded(
        address indexed consumerAppId, bytes32 indexed deliveryHash, uint256 indexed sequence, uint256 timestamp
    );

    address public owner;
    address public pendingOwner;
    uint256 public constant MIN_ORACLE_UPGRADE_DELAY = 2 days;
    uint256 public constant MAX_ORACLE_UPGRADE_DELAY = 365 days;
    uint256 public immutable ORACLE_UPGRADE_DELAY;
    /// @notice When true, a registered consumer policy is not an active
    /// authorization until the exact oracle, consumer, and KMS release has
    /// completed every one-way freeze. This is constructor-bound so a fresh
    /// production deployment cannot expose a partially configured consumer.
    bool public immutable productionRelease;

    bool public allowAnyDevice;
    bool public oracleCodeFrozen;
    bool public consumerRegistryFrozen;
    bool public consumerManagerAdditionsFrozen;
    bool public kmsBindingFrozen;

    uint256 public allowedOracleComposeHashCount;
    uint256 public pendingOracleComposeHashCount;
    uint256 public allowedDeviceIdCount;
    uint256 public consumerManagerCount;
    uint256 public totalConsumerComposeHashCount;

    bytes32 public releaseOracleComposeHash;
    bytes32 public releaseDeviceId;
    address public releaseConsumerManager;
    address public releaseConsumerAppId;
    bytes32 public releaseConsumerComposeHash;

    mapping(bytes32 => bool) public allowedOracleComposeHashes;
    mapping(bytes32 => uint256) public pendingOracleComposeHashes;
    mapping(bytes32 => bool) public allowedDeviceIds;

    mapping(address => bool) public consumerManagers;
    mapping(address => mapping(bytes32 => bool)) private _allowedConsumerComposeHashes;
    mapping(address => uint256) private _consumerComposeHashCounts;
    /// @notice Emergency kill switch: a revoked consumer is unauthorized for ALL
    /// its compose hashes, immediately, and even after the registry is frozen.
    mapping(address => bool) public consumerEmergencyRevoked;
    /// @notice Count of hashed OTP-delivery audit records emitted per consumer.
    mapping(address => uint256) public otpDeliveryCount;

    address public kmsContract;
    bytes32 public kmsRuntimeCodeHash;
    address public kmsImplementation;
    bytes32 public kmsImplementationRuntimeCodeHash;
    bytes32 public kmsRegistrationTxHash;
    uint64 public kmsRegistrationBlock;
    bytes32 public kmsRegistrationBlockHash;
    bytes32 public targetBootInfoHash;
    bytes32 public restartKeyDerivationProofHash;

    address public pendingKmsContract;
    bytes32 public pendingKmsRuntimeCodeHash;
    address public pendingKmsImplementation;
    bytes32 public pendingKmsImplementationRuntimeCodeHash;
    bytes32 public pendingKmsRegistrationTxHash;
    uint64 public pendingKmsRegistrationBlock;
    bytes32 public pendingKmsRegistrationBlockHash;
    bytes32 public pendingTargetBootInfoHash;
    bytes32 public pendingRestartKeyDerivationProofHash;
    uint256 public pendingKmsBindingActivatesAt;

    constructor(
        address initialOwner,
        uint256 initialOracleUpgradeDelay,
        bool initialAllowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialOracleComposeHash,
        bool initialProductionRelease
    ) {
        _requireUnprivilegedAddress(initialOwner);
        if (
            initialOracleUpgradeDelay < MIN_ORACLE_UPGRADE_DELAY || initialOracleUpgradeDelay > MAX_ORACLE_UPGRADE_DELAY
        ) revert InvalidUpgradeDelay();

        owner = initialOwner;
        ORACLE_UPGRADE_DELAY = initialOracleUpgradeDelay;
        productionRelease = initialProductionRelease;
        allowAnyDevice = initialAllowAnyDevice;

        if (initialDeviceId != bytes32(0)) {
            allowedDeviceIds[initialDeviceId] = true;
            allowedDeviceIdCount = 1;
            emit DeviceAdded(initialDeviceId);
        }

        if (initialOracleComposeHash != bytes32(0)) {
            allowedOracleComposeHashes[initialOracleComposeHash] = true;
            allowedOracleComposeHashCount = 1;
            emit OracleComposeHashActivated(initialOracleComposeHash);
        }

        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    modifier onlyOwnerOrConsumerManager() {
        _onlyOwnerOrConsumerManager();
        _;
    }

    modifier whenOracleCodeMutable() {
        _whenOracleCodeMutable();
        _;
    }

    modifier whenConsumerRegistryMutable() {
        _whenConsumerRegistryMutable();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _onlyOwnerOrConsumerManager() internal view {
        if (msg.sender != owner && !consumerManagers[msg.sender]) {
            revert NotOwnerOrConsumerManager();
        }
    }

    function _whenOracleCodeMutable() internal view {
        if (oracleCodeFrozen) revert OracleCodeFrozen();
    }

    function _whenConsumerRegistryMutable() internal view {
        if (consumerRegistryFrozen) revert ConsumerRegistryFrozen();
    }

    function _requireUnprivilegedAddress(address account) internal view {
        if (account == address(0)) revert ZeroAddress();
        if (account == address(this)) revert RoleCollision();
    }

    function _requireOwnerCandidate(address candidate) internal view {
        _requireUnprivilegedAddress(candidate);
        if (consumerManagers[candidate] || _consumerComposeHashCounts[candidate] != 0) revert RoleCollision();
    }

    /// @notice Start a two-step ownership transfer. The nominee must explicitly accept.
    function transferOwnership(address newOwner) external onlyOwner {
        _requireOwnerCandidate(newOwner);
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function cancelOwnershipTransfer() external onlyOwner {
        address cancelled = pendingOwner;
        if (cancelled == address(0)) revert NotPendingOwner();
        pendingOwner = address(0);
        emit OwnershipTransferCancelled(owner, cancelled);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        _requireOwnerCandidate(msg.sender);
        address previous = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previous, msg.sender);
    }

    /// @notice Add or remove a consumer manager.
    /// @dev After additions are frozen, removal remains available as a permanent
    ///      incident-response action; a removed manager cannot be restored.
    function setConsumerManager(address account, bool allowed) external onlyOwner {
        _requireUnprivilegedAddress(account);
        if (account == owner || account == pendingOwner) revert RoleCollision();
        bool current = consumerManagers[account];
        if (current == allowed) {
            if (allowed) revert AlreadyAllowed();
            revert NotAllowed();
        }
        if (allowed && consumerManagerAdditionsFrozen) revert ConsumerManagerAdditionsFrozen();
        consumerManagers[account] = allowed;
        if (allowed) {
            consumerManagerCount += 1;
        } else {
            consumerManagerCount -= 1;
        }
        emit ConsumerManagerSet(account, allowed);
    }

    function freezeConsumerManagerAdditions(address expectedManager) external onlyOwner {
        if (consumerManagerAdditionsFrozen) revert ConsumerManagerAdditionsFrozen();
        _requireUnprivilegedAddress(expectedManager);
        if (
            expectedManager == owner || !consumerManagers[expectedManager] || consumerManagerCount != 1
                || pendingOwner != address(0)
        ) revert ReleaseConfigurationIncomplete();
        releaseConsumerManager = expectedManager;
        consumerManagerAdditionsFrozen = true;
        emit ConsumerManagerAdditionsFrozenForever(expectedManager);
    }

    function proposeOracleComposeHash(bytes32 composeHash) external onlyOwner whenOracleCodeMutable {
        if (composeHash == bytes32(0)) revert ZeroHash();
        if (allowedOracleComposeHashes[composeHash]) revert AlreadyAllowed();
        if (pendingOracleComposeHashes[composeHash] != 0) revert AlreadyPending();

        uint256 activatesAt = block.timestamp + ORACLE_UPGRADE_DELAY;
        pendingOracleComposeHashes[composeHash] = activatesAt;
        pendingOracleComposeHashCount += 1;
        emit OracleComposeHashProposed(composeHash, activatesAt);
    }

    function activateOracleComposeHash(bytes32 composeHash) external whenOracleCodeMutable {
        uint256 activatesAt = pendingOracleComposeHashes[composeHash];
        if (activatesAt == 0) revert NotPending();
        if (block.timestamp < activatesAt) revert ActivationTooEarly(activatesAt);

        delete pendingOracleComposeHashes[composeHash];
        pendingOracleComposeHashCount -= 1;
        allowedOracleComposeHashes[composeHash] = true;
        allowedOracleComposeHashCount += 1;
        emit OracleComposeHashActivated(composeHash);
    }

    function cancelOracleComposeHashProposal(bytes32 composeHash) external onlyOwner whenOracleCodeMutable {
        if (pendingOracleComposeHashes[composeHash] == 0) revert NotPending();
        delete pendingOracleComposeHashes[composeHash];
        pendingOracleComposeHashCount -= 1;
        emit OracleComposeHashProposalCancelled(composeHash);
    }

    /// @notice Permanently remove an oracle compose hash, including after freeze.
    function removeOracleComposeHash(bytes32 composeHash) external onlyOwner {
        if (!allowedOracleComposeHashes[composeHash]) revert NotAllowed();
        allowedOracleComposeHashes[composeHash] = false;
        allowedOracleComposeHashCount -= 1;
        emit OracleComposeHashRemoved(composeHash);
    }

    function setAllowAnyDevice(bool allowAny) external onlyOwner whenOracleCodeMutable {
        allowAnyDevice = allowAny;
        emit AllowAnyDeviceSet(allowAny);
    }

    function addDevice(bytes32 deviceId) external onlyOwner whenOracleCodeMutable {
        if (deviceId == bytes32(0)) revert ZeroHash();
        if (allowedDeviceIds[deviceId]) revert AlreadyAllowed();
        allowedDeviceIds[deviceId] = true;
        allowedDeviceIdCount += 1;
        emit DeviceAdded(deviceId);
    }

    /// @notice Permanently remove a device, including after freeze.
    function removeDevice(bytes32 deviceId) external onlyOwner {
        if (!allowedDeviceIds[deviceId]) revert NotAllowed();
        allowedDeviceIds[deviceId] = false;
        allowedDeviceIdCount -= 1;
        emit DeviceRemoved(deviceId);
    }

    function addConsumerComposeHash(address consumerAppId, bytes32 composeHash)
        external
        onlyOwnerOrConsumerManager
        whenConsumerRegistryMutable
    {
        _requireUnprivilegedAddress(consumerAppId);
        if (consumerAppId == owner || consumerAppId == pendingOwner) revert RoleCollision();
        if (composeHash == bytes32(0)) revert ZeroHash();
        if (_allowedConsumerComposeHashes[consumerAppId][composeHash]) revert AlreadyAllowed();

        _allowedConsumerComposeHashes[consumerAppId][composeHash] = true;
        _consumerComposeHashCounts[consumerAppId] += 1;
        totalConsumerComposeHashCount += 1;

        emit ConsumerComposeHashAdded(consumerAppId, composeHash);
    }

    function removeConsumerComposeHash(address consumerAppId, bytes32 composeHash)
        external
        onlyOwnerOrConsumerManager
        whenConsumerRegistryMutable
    {
        if (!_allowedConsumerComposeHashes[consumerAppId][composeHash]) revert NotAllowed();

        _allowedConsumerComposeHashes[consumerAppId][composeHash] = false;
        _consumerComposeHashCounts[consumerAppId] -= 1;
        totalConsumerComposeHashCount -= 1;

        emit ConsumerComposeHashRemoved(consumerAppId, composeHash);
    }

    /// @notice Close oracle compose/device additions around one exact target boot policy.
    /// @dev Pending compose proposals and broad device admission make freezing invalid.
    function freezeOracleCodeAuth(bytes32 expectedComposeHash, bytes32 expectedDeviceId)
        external
        onlyOwner
        whenOracleCodeMutable
    {
        if (
            expectedComposeHash == bytes32(0) || expectedDeviceId == bytes32(0) || allowAnyDevice
                || allowedOracleComposeHashCount != 1 || pendingOracleComposeHashCount != 0 || allowedDeviceIdCount != 1
                || !allowedOracleComposeHashes[expectedComposeHash] || !allowedDeviceIds[expectedDeviceId]
                || pendingOwner != address(0)
        ) revert ReleaseConfigurationIncomplete();
        releaseOracleComposeHash = expectedComposeHash;
        releaseDeviceId = expectedDeviceId;
        oracleCodeFrozen = true;
        emit OracleCodeAuthFrozen(expectedComposeHash, expectedDeviceId);
    }

    /// @notice Close consumer membership around one exact consumer/compose binding.
    function freezeConsumerRegistry(address expectedConsumerAppId, bytes32 expectedComposeHash)
        external
        onlyOwner
        whenConsumerRegistryMutable
    {
        if (
            !oracleCodeFrozen || !consumerManagerAdditionsFrozen || expectedConsumerAppId == address(0)
                || expectedComposeHash == bytes32(0) || expectedConsumerAppId != releaseConsumerManager
                || totalConsumerComposeHashCount != 1 || _consumerComposeHashCounts[expectedConsumerAppId] != 1
                || !_allowedConsumerComposeHashes[expectedConsumerAppId][expectedComposeHash]
                || consumerEmergencyRevoked[expectedConsumerAppId] || pendingOwner != address(0)
        ) revert ReleaseConfigurationIncomplete();
        releaseConsumerAppId = expectedConsumerAppId;
        releaseConsumerComposeHash = expectedComposeHash;
        consumerRegistryFrozen = true;
        emit ConsumerRegistryFrozenForever(expectedConsumerAppId, expectedComposeHash);
    }

    /// @notice Stage a binding to the exact KMS proxy/implementation and external
    ///         registration/restart evidence used for this release.
    /// @dev EVM contracts cannot read historical receipts. The Base ceremony and
    ///      web validator must independently prove the transaction input, receipt,
    ///      block hash, AppRegistered log, and registeredApps readback before this
    ///      commitment is treated as live evidence.
    function proposeKmsBinding(
        address expectedKmsContract,
        bytes32 expectedKmsRuntimeCodeHash,
        address expectedKmsImplementation,
        bytes32 expectedKmsImplementationRuntimeCodeHash,
        bytes32 registrationTxHash,
        uint64 registrationBlock,
        bytes32 registrationBlockHash,
        AppBootInfo calldata targetBootInfo,
        bytes32 restartProofHash
    ) external onlyOwner {
        if (kmsBindingFrozen) revert KmsBindingFrozen();
        if (pendingKmsBindingActivatesAt != 0) revert AlreadyPending();
        _requireUnprivilegedAddress(expectedKmsContract);
        _requireUnprivilegedAddress(expectedKmsImplementation);
        if (
            expectedKmsRuntimeCodeHash == bytes32(0) || expectedKmsImplementationRuntimeCodeHash == bytes32(0)
                || registrationTxHash == bytes32(0) || registrationBlock == 0 || registrationBlockHash == bytes32(0)
                || restartProofHash == bytes32(0) || !oracleCodeFrozen || targetBootInfo.appId != address(this)
                || targetBootInfo.composeHash != releaseOracleComposeHash || targetBootInfo.deviceId != releaseDeviceId
                || targetBootInfo.instanceId == address(0) || targetBootInfo.mrAggregated == bytes32(0)
                || targetBootInfo.mrSystem == bytes32(0) || targetBootInfo.osImageHash == bytes32(0)
        ) revert ReleaseConfigurationIncomplete();
        _requireRuntimeCodeHash(expectedKmsContract, expectedKmsRuntimeCodeHash);
        _requireRuntimeCodeHash(expectedKmsImplementation, expectedKmsImplementationRuntimeCodeHash);
        if (registrationBlock >= block.number) revert RegistrationBlockUnavailable();
        // The registered-app read is independently meaningful before final
        // activation. Boot authorization is deliberately deferred: a real KMS
        // delegates that decision back to this IAppAuth, which must remain
        // deny-all until every raw release membership and KMS field is frozen.
        _requireRegistered(expectedKmsContract);

        pendingKmsContract = expectedKmsContract;
        pendingKmsRuntimeCodeHash = expectedKmsRuntimeCodeHash;
        pendingKmsImplementation = expectedKmsImplementation;
        pendingKmsImplementationRuntimeCodeHash = expectedKmsImplementationRuntimeCodeHash;
        pendingKmsRegistrationTxHash = registrationTxHash;
        pendingKmsRegistrationBlock = registrationBlock;
        pendingKmsRegistrationBlockHash = registrationBlockHash;
        pendingTargetBootInfoHash = _bootInfoHash(targetBootInfo);
        pendingRestartKeyDerivationProofHash = restartProofHash;
        pendingKmsBindingActivatesAt = block.timestamp + ORACLE_UPGRADE_DELAY;
        emit KmsBindingProposed(
            expectedKmsContract,
            expectedKmsImplementation,
            registrationTxHash,
            pendingKmsBindingActivatesAt,
            pendingTargetBootInfoHash,
            restartProofHash
        );
    }

    function cancelKmsBindingProposal() external onlyOwner {
        if (kmsBindingFrozen) revert KmsBindingFrozen();
        if (pendingKmsBindingActivatesAt == 0) revert NotPending();
        address cancelledKms = pendingKmsContract;
        bytes32 cancelledRegistrationTx = pendingKmsRegistrationTxHash;
        _clearPendingKmsBinding();
        emit KmsBindingProposalCancelled(cancelledKms, cancelledRegistrationTx);
    }

    /// @notice Activate and permanently freeze the exact KMS/evidence binding.
    /// @dev Registration and target boot authorization are re-read from the KMS
    ///      after the full immutable delay. A mutable KMS policy can later deny
    ///      this boot; web/activation validators must therefore repeat the same
    ///      target boot read at their pinned release block.
    function activateAndFreezeKmsBinding(AppBootInfo calldata targetBootInfo) external {
        if (kmsBindingFrozen) revert KmsBindingFrozen();
        uint256 activatesAt = pendingKmsBindingActivatesAt;
        if (activatesAt == 0) revert NotPending();
        if (block.timestamp < activatesAt) revert ActivationTooEarly(activatesAt);
        if (_bootInfoHash(targetBootInfo) != pendingTargetBootInfoHash) revert ReleaseConfigurationIncomplete();
        _requireRuntimeCodeHash(pendingKmsContract, pendingKmsRuntimeCodeHash);
        _requireRuntimeCodeHash(pendingKmsImplementation, pendingKmsImplementationRuntimeCodeHash);
        // Tentatively install and freeze the exact binding before asking KMS
        // for the delegated boot decision. If either registration or delegated
        // authorization fails, the transaction reverts atomically and none of
        // these writes survive.
        kmsContract = pendingKmsContract;
        kmsRuntimeCodeHash = pendingKmsRuntimeCodeHash;
        kmsImplementation = pendingKmsImplementation;
        kmsImplementationRuntimeCodeHash = pendingKmsImplementationRuntimeCodeHash;
        kmsRegistrationTxHash = pendingKmsRegistrationTxHash;
        kmsRegistrationBlock = pendingKmsRegistrationBlock;
        kmsRegistrationBlockHash = pendingKmsRegistrationBlockHash;
        targetBootInfoHash = pendingTargetBootInfoHash;
        restartKeyDerivationProofHash = pendingRestartKeyDerivationProofHash;
        _clearPendingKmsBinding();
        kmsBindingFrozen = true;

        _requireRegisteredAndAllowed(kmsContract, targetBootInfo);

        emit KmsBindingActivatedAndFrozen(
            kmsContract,
            kmsImplementation,
            kmsRegistrationTxHash,
            kmsRegistrationBlock,
            targetBootInfoHash,
            restartKeyDerivationProofHash
        );
    }

    function _clearPendingKmsBinding() internal {
        pendingKmsContract = address(0);
        pendingKmsRuntimeCodeHash = bytes32(0);
        pendingKmsImplementation = address(0);
        pendingKmsImplementationRuntimeCodeHash = bytes32(0);
        pendingKmsRegistrationTxHash = bytes32(0);
        pendingKmsRegistrationBlock = 0;
        pendingKmsRegistrationBlockHash = bytes32(0);
        pendingTargetBootInfoHash = bytes32(0);
        pendingRestartKeyDerivationProofHash = bytes32(0);
        pendingKmsBindingActivatesAt = 0;
    }

    function _requireRuntimeCodeHash(address account, bytes32 expected) internal view {
        if (account.code.length == 0 || account.codehash != expected) revert RuntimeCodeHashMismatch();
    }

    function _requireRegisteredAndAllowed(address targetKms, AppBootInfo calldata bootInfo) internal view {
        _requireRegistered(targetKms);
        try IDstackKmsRead(targetKms).isAppAllowed(bootInfo) returns (bool allowed, string memory) {
            if (!allowed) revert KmsBootAuthorizationDenied();
        } catch {
            revert KmsBootAuthorizationDenied();
        }
    }

    function _requireRegistered(address targetKms) internal view {
        bool registered;
        try IDstackKmsRead(targetKms).registeredApps(address(this)) returns (bool value) {
            registered = value;
        } catch {
            revert KmsRegistrationMissing();
        }
        if (!registered) revert KmsRegistrationMissing();
    }

    function _bootInfoHash(AppBootInfo calldata bootInfo) internal pure returns (bytes32) {
        return keccak256(abi.encode(bootInfo));
    }

    /// @notice Immediately revoke ALL authorization for a consumer (kill switch).
    /// @dev Not timelocked and NOT gated by the registry freeze. Once the registry
    ///      is frozen, this action is permanent because restoreConsumer is closed.
    function emergencyRevokeConsumer(address consumerAppId) external onlyOwnerOrConsumerManager {
        if (consumerAppId == address(0)) revert ZeroAddress();
        if (consumerEmergencyRevoked[consumerAppId]) revert AlreadyAllowed();
        consumerEmergencyRevoked[consumerAppId] = true;
        emit ConsumerEmergencyRevoked(consumerAppId);
    }

    /// @notice Clear an emergency revocation only before final registry freeze.
    function restoreConsumer(address consumerAppId) external onlyOwner whenConsumerRegistryMutable {
        if (!consumerEmergencyRevoked[consumerAppId]) revert NotAllowed();
        consumerEmergencyRevoked[consumerAppId] = false;
        emit ConsumerEmergencyRestored(consumerAppId);
    }

    /// @notice Record a hashed OTP-delivery audit event for dispute resolution.
    function recordOtpDelivery(address consumerAppId, bytes32 deliveryHash)
        external
        onlyOwnerOrConsumerManager
        returns (uint256 sequence)
    {
        if (consumerAppId == address(0)) revert ZeroAddress();
        if (deliveryHash == bytes32(0)) revert ZeroHash();
        if (consumerEmergencyRevoked[consumerAppId]) revert NotAllowed();
        if (productionRelease && (!_releaseConfigurationReady() || consumerAppId != releaseConsumerAppId)) {
            revert ReleaseConfigurationIncomplete();
        }

        sequence = ++otpDeliveryCount[consumerAppId];
        emit OtpDeliveryRecorded(consumerAppId, deliveryHash, sequence, block.timestamp);
    }

    function isConsumerAuthorized(address consumerAppId, bytes32 composeHash) external view returns (bool) {
        if (consumerEmergencyRevoked[consumerAppId]) return false;
        if (productionRelease && !_releaseConfigurationReady()) return false;
        return _allowedConsumerComposeHashes[consumerAppId][composeHash];
    }

    /// @notice Raw ceremony-state membership. This is deliberately distinct
    /// from active authorization: production consumers remain unauthorized
    /// until `releaseConfigurationReady()` is true.
    function isConsumerComposeHashRegistered(address consumerAppId, bytes32 composeHash) external view returns (bool) {
        return _allowedConsumerComposeHashes[consumerAppId][composeHash];
    }

    function consumerComposeHashCount(address consumerAppId) external view returns (uint256) {
        return _consumerComposeHashCounts[consumerAppId];
    }

    /// @notice Dynamic release-readiness read. Any post-freeze emergency removal
    ///         makes it false even though the one-way freeze flags stay true.
    /// @dev Target boot authorization itself must be re-read from KMS using the
    ///      manifest boot tuple; only its hash is retained on-chain.
    function releaseConfigurationReady() external view returns (bool) {
        return _releaseConfigurationReady();
    }

    function _releaseConfigurationReady() internal view returns (bool) {
        if (
            !oracleCodeFrozen || !consumerRegistryFrozen || !consumerManagerAdditionsFrozen || !kmsBindingFrozen
                || allowAnyDevice || pendingOwner != address(0) || allowedOracleComposeHashCount != 1
                || pendingOracleComposeHashCount != 0 || allowedDeviceIdCount != 1 || consumerManagerCount != 1
                || totalConsumerComposeHashCount != 1 || !allowedOracleComposeHashes[releaseOracleComposeHash]
                || !allowedDeviceIds[releaseDeviceId] || !consumerManagers[releaseConsumerManager]
                || releaseConsumerManager != releaseConsumerAppId
                || _consumerComposeHashCounts[releaseConsumerAppId] != 1
                || !_allowedConsumerComposeHashes[releaseConsumerAppId][releaseConsumerComposeHash]
                || consumerEmergencyRevoked[releaseConsumerAppId] || pendingKmsBindingActivatesAt != 0
                || kmsContract.code.length == 0 || kmsContract.codehash != kmsRuntimeCodeHash
                || kmsImplementation.code.length == 0 || kmsImplementation.codehash != kmsImplementationRuntimeCodeHash
        ) return false;
        (bool ok, bytes memory value) =
            kmsContract.staticcall(abi.encodeWithSelector(IDstackKmsRead.registeredApps.selector, address(this)));
        return ok && value.length == 32 && abi.decode(value, (bool));
    }

    function isAppAllowed(AppBootInfo calldata bootInfo)
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        if (bootInfo.appId != address(this)) {
            return (false, "App ID mismatch");
        }

        // Raw compose/device membership is only ceremony state. A production
        // KMS admission must remain deny-all until every release binding is
        // frozen, the exact consumer remains live, and KMS still reports this
        // auth contract as registered. Emergency removal therefore takes
        // effect dynamically even after all one-way freezes.
        if (productionRelease && !_releaseConfigurationReady()) {
            return (false, "Release not ready");
        }

        if (!allowedOracleComposeHashes[bootInfo.composeHash]) {
            return (false, "Compose hash not allowed");
        }

        if (!allowAnyDevice && !allowedDeviceIds[bootInfo.deviceId]) {
            return (false, "Device not allowed");
        }

        return (true, "");
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IAppAuth).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
