// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAppAuth, IERC165} from "./interfaces/IAppAuth.sol";

/// @title EmailOracleAuth
/// @notice dstack-compatible auth contract for the email oracle.
/// @dev Separates oracle boot authorization from OTP consumer authorization.
contract EmailOracleAuth is IAppAuth {
    error NotOwner();
    error NotOwnerOrConsumerManager();
    error ZeroAddress();
    error ZeroHash();
    error OracleCodeFrozen();
    error ConsumerRegistryFrozen();
    error AlreadyAllowed();
    error NotAllowed();
    error AlreadyPending();
    error NotPending();
    error ActivationTooEarly(uint256 activatesAt);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ConsumerManagerSet(address indexed account, bool allowed);

    event OracleComposeHashProposed(bytes32 indexed composeHash, uint256 activatesAt);
    event OracleComposeHashActivated(bytes32 indexed composeHash);
    event OracleComposeHashProposalCancelled(bytes32 indexed composeHash);
    event OracleComposeHashRemoved(bytes32 indexed composeHash);

    event DeviceAdded(bytes32 indexed deviceId);
    event DeviceRemoved(bytes32 indexed deviceId);
    event AllowAnyDeviceSet(bool allowAnyDevice);

    event ConsumerComposeHashAdded(address indexed consumerAppId, bytes32 indexed composeHash);
    event ConsumerComposeHashRemoved(address indexed consumerAppId, bytes32 indexed composeHash);

    event OracleCodeAuthFrozen();
    event ConsumerRegistryFrozenForever();

    event ConsumerEmergencyRevoked(address indexed consumerAppId);
    event ConsumerEmergencyRestored(address indexed consumerAppId);

    /// @dev Hashed OTP-delivery audit record for dispute resolution. `deliveryHash`
    /// is an off-chain commitment to the delivery context (consumer, request id,
    /// OTP hash) — never the raw OTP. `sequence` is the per-consumer ordinal so
    /// gaps/duplicates are detectable.
    event OtpDeliveryRecorded(
        address indexed consumerAppId,
        bytes32 indexed deliveryHash,
        uint256 indexed sequence,
        uint256 timestamp
    );

    address public owner;
    uint256 public immutable ORACLE_UPGRADE_DELAY;

    bool public allowAnyDevice;
    bool public oracleCodeFrozen;
    bool public consumerRegistryFrozen;

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

    constructor(
        address initialOwner,
        uint256 initialOracleUpgradeDelay,
        bool initialAllowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialOracleComposeHash
    ) {
        if (initialOwner == address(0)) revert ZeroAddress();

        owner = initialOwner;
        ORACLE_UPGRADE_DELAY = initialOracleUpgradeDelay;
        allowAnyDevice = initialAllowAnyDevice;

        if (initialDeviceId != bytes32(0)) {
            allowedDeviceIds[initialDeviceId] = true;
            emit DeviceAdded(initialDeviceId);
        }

        if (initialOracleComposeHash != bytes32(0)) {
            allowedOracleComposeHashes[initialOracleComposeHash] = true;
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

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setConsumerManager(address account, bool allowed) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        consumerManagers[account] = allowed;
        emit ConsumerManagerSet(account, allowed);
    }

    function proposeOracleComposeHash(bytes32 composeHash)
        external
        onlyOwner
        whenOracleCodeMutable
    {
        if (composeHash == bytes32(0)) revert ZeroHash();
        if (allowedOracleComposeHashes[composeHash]) revert AlreadyAllowed();
        if (pendingOracleComposeHashes[composeHash] != 0) revert AlreadyPending();

        uint256 activatesAt = block.timestamp + ORACLE_UPGRADE_DELAY;
        pendingOracleComposeHashes[composeHash] = activatesAt;
        emit OracleComposeHashProposed(composeHash, activatesAt);
    }

    function activateOracleComposeHash(bytes32 composeHash)
        external
        whenOracleCodeMutable
    {
        uint256 activatesAt = pendingOracleComposeHashes[composeHash];
        if (activatesAt == 0) revert NotPending();
        if (block.timestamp < activatesAt) revert ActivationTooEarly(activatesAt);

        delete pendingOracleComposeHashes[composeHash];
        allowedOracleComposeHashes[composeHash] = true;
        emit OracleComposeHashActivated(composeHash);
    }

    function cancelOracleComposeHashProposal(bytes32 composeHash)
        external
        onlyOwner
        whenOracleCodeMutable
    {
        if (pendingOracleComposeHashes[composeHash] == 0) revert NotPending();
        delete pendingOracleComposeHashes[composeHash];
        emit OracleComposeHashProposalCancelled(composeHash);
    }

    function removeOracleComposeHash(bytes32 composeHash)
        external
        onlyOwner
        whenOracleCodeMutable
    {
        if (!allowedOracleComposeHashes[composeHash]) revert NotAllowed();
        allowedOracleComposeHashes[composeHash] = false;
        emit OracleComposeHashRemoved(composeHash);
    }

    function setAllowAnyDevice(bool allowAny)
        external
        onlyOwner
        whenOracleCodeMutable
    {
        allowAnyDevice = allowAny;
        emit AllowAnyDeviceSet(allowAny);
    }

    function addDevice(bytes32 deviceId)
        external
        onlyOwner
        whenOracleCodeMutable
    {
        if (deviceId == bytes32(0)) revert ZeroHash();
        if (allowedDeviceIds[deviceId]) revert AlreadyAllowed();
        allowedDeviceIds[deviceId] = true;
        emit DeviceAdded(deviceId);
    }

    function removeDevice(bytes32 deviceId)
        external
        onlyOwner
        whenOracleCodeMutable
    {
        if (!allowedDeviceIds[deviceId]) revert NotAllowed();
        allowedDeviceIds[deviceId] = false;
        emit DeviceRemoved(deviceId);
    }

    function addConsumerComposeHash(address consumerAppId, bytes32 composeHash)
        external
        onlyOwnerOrConsumerManager
        whenConsumerRegistryMutable
    {
        if (consumerAppId == address(0)) revert ZeroAddress();
        if (composeHash == bytes32(0)) revert ZeroHash();
        if (_allowedConsumerComposeHashes[consumerAppId][composeHash]) revert AlreadyAllowed();

        _allowedConsumerComposeHashes[consumerAppId][composeHash] = true;
        _consumerComposeHashCounts[consumerAppId] += 1;

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

        emit ConsumerComposeHashRemoved(consumerAppId, composeHash);
    }

    function freezeOracleCodeAuth() external onlyOwner whenOracleCodeMutable {
        oracleCodeFrozen = true;
        emit OracleCodeAuthFrozen();
    }

    function freezeConsumerRegistry() external onlyOwner whenConsumerRegistryMutable {
        consumerRegistryFrozen = true;
        emit ConsumerRegistryFrozenForever();
    }

    /// @notice Immediately revoke ALL authorization for a consumer (kill switch).
    /// @dev Not timelocked and NOT gated by the registry freeze — a compromised
    /// consumer must be killable even after the registry is frozen. Only reduces
    /// access, so owner or a consumer manager may trigger it.
    function emergencyRevokeConsumer(address consumerAppId)
        external
        onlyOwnerOrConsumerManager
    {
        if (consumerAppId == address(0)) revert ZeroAddress();
        if (consumerEmergencyRevoked[consumerAppId]) revert AlreadyAllowed();
        consumerEmergencyRevoked[consumerAppId] = true;
        emit ConsumerEmergencyRevoked(consumerAppId);
    }

    /// @notice Clear an emergency revocation (recovery after a false alarm).
    /// @dev Owner-only and only while the registry is still mutable: once the
    /// registry is frozen, an emergency kill is permanent (final config cannot
    /// re-enable a consumer). Re-enabling access is more privileged than killing.
    function restoreConsumer(address consumerAppId)
        external
        onlyOwner
        whenConsumerRegistryMutable
    {
        if (!consumerEmergencyRevoked[consumerAppId]) revert NotAllowed();
        consumerEmergencyRevoked[consumerAppId] = false;
        emit ConsumerEmergencyRestored(consumerAppId);
    }

    /// @notice Record a hashed OTP-delivery audit event for dispute resolution.
    /// @dev `deliveryHash` is an off-chain commitment to the delivery context
    /// (consumer, request id, OTP hash); the raw OTP never touches the chain.
    /// Fail-closed: a delivery cannot be recorded for an emergency-revoked
    /// consumer. Returns the per-consumer sequence number of this record.
    function recordOtpDelivery(address consumerAppId, bytes32 deliveryHash)
        external
        onlyOwnerOrConsumerManager
        returns (uint256 sequence)
    {
        if (consumerAppId == address(0)) revert ZeroAddress();
        if (deliveryHash == bytes32(0)) revert ZeroHash();
        if (consumerEmergencyRevoked[consumerAppId]) revert NotAllowed();

        sequence = ++otpDeliveryCount[consumerAppId];
        emit OtpDeliveryRecorded(consumerAppId, deliveryHash, sequence, block.timestamp);
    }

    function isConsumerAuthorized(address consumerAppId, bytes32 composeHash)
        external
        view
        returns (bool)
    {
        if (consumerEmergencyRevoked[consumerAppId]) return false;
        return _allowedConsumerComposeHashes[consumerAppId][composeHash];
    }

    function consumerComposeHashCount(address consumerAppId)
        external
        view
        returns (uint256)
    {
        return _consumerComposeHashCounts[consumerAppId];
    }

    function isAppAllowed(
        AppBootInfo calldata bootInfo
    ) external view override returns (bool isAllowed, string memory reason) {
        if (bootInfo.appId != address(this)) {
            return (false, "App ID mismatch");
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
