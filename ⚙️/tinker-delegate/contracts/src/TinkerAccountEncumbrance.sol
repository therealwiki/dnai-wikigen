// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title TinkerAccountEncumbrance
/// @notice Minimal on-chain policy surface for a TEE-owned Tinker account.
///         It does not custody payment cards or Tinker credentials. It records
///         bounded authorization/audit events for account funding and spend.
contract TinkerAccountEncumbrance {
    enum OperationKind {
        AddPaymentMethod,
        AddBalance,
        SpendTinkerCompute,
        ManualPrefund
    }

    struct OperationRecord {
        OperationKind kind;
        address requester;
        address authorizer;
        bytes32 composeHash;
        uint256 amountWei;
        bool settled;
        bool success;
        bytes32 receiptHash;
    }

    error NotOwner();
    error NotOwnerOrManager();
    error ZeroAddress();
    error ZeroHash();
    error MeasurementsFrozen();
    error EmergencyHalted();
    error ComposeHashNotApproved();
    error AmountExceedsPolicy();
    error DuplicateOperation();
    error UnknownOperation();
    error AlreadySettled();
    error NonZeroAmountForPaymentMethod();
    error SelfApprovalNotAllowed();

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ManagerSet(address indexed manager, bool allowed);
    event AccountCommitmentUpdated(bytes32 indexed previousCommitment, bytes32 indexed newCommitment);
    event ComposeHashApproved(bytes32 indexed composeHash);
    event ComposeHashRevoked(bytes32 indexed composeHash);
    event MeasurementsFrozenForever();
    event EmergencyHaltSet(bool halted);
    event FundingPolicySet(uint256 maxAddBalanceWei, uint256 maxSpendWei);
    event OperationAuthorized(
        bytes32 indexed operationId,
        OperationKind indexed kind,
        address indexed requester,
        address authorizer,
        bytes32 composeHash,
        uint256 amountWei
    );
    event OperationSettled(
        bytes32 indexed operationId,
        bool success,
        bytes32 receiptHash
    );

    address public owner;
    bytes32 public accountCommitment;
    uint256 public maxAddBalanceWei;
    uint256 public maxSpendWei;
    bool public emergencyHalted;
    bool public measurementsFrozen;

    mapping(address => bool) public managers;
    mapping(bytes32 => bool) public approvedComposeHashes;
    mapping(bytes32 => OperationRecord) private _operations;

    constructor(
        address initialOwner,
        bytes32 initialAccountCommitment,
        bytes32 initialComposeHash,
        uint256 initialMaxAddBalanceWei,
        uint256 initialMaxSpendWei
    ) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (initialAccountCommitment == bytes32(0)) revert ZeroHash();
        if (initialComposeHash == bytes32(0)) revert ZeroHash();

        owner = initialOwner;
        accountCommitment = initialAccountCommitment;
        maxAddBalanceWei = initialMaxAddBalanceWei;
        maxSpendWei = initialMaxSpendWei;
        approvedComposeHashes[initialComposeHash] = true;

        emit OwnershipTransferred(address(0), initialOwner);
        emit AccountCommitmentUpdated(bytes32(0), initialAccountCommitment);
        emit ComposeHashApproved(initialComposeHash);
        emit FundingPolicySet(initialMaxAddBalanceWei, initialMaxSpendWei);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyOwnerOrManager() {
        if (msg.sender != owner && !managers[msg.sender]) revert NotOwnerOrManager();
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setManager(address manager, bool allowed) external onlyOwner {
        if (manager == address(0)) revert ZeroAddress();
        managers[manager] = allowed;
        emit ManagerSet(manager, allowed);
    }

    function setAccountCommitment(bytes32 newAccountCommitment) external onlyOwner {
        if (newAccountCommitment == bytes32(0)) revert ZeroHash();
        emit AccountCommitmentUpdated(accountCommitment, newAccountCommitment);
        accountCommitment = newAccountCommitment;
    }

    function setFundingPolicy(uint256 newMaxAddBalanceWei, uint256 newMaxSpendWei)
        external
        onlyOwner
    {
        maxAddBalanceWei = newMaxAddBalanceWei;
        maxSpendWei = newMaxSpendWei;
        emit FundingPolicySet(newMaxAddBalanceWei, newMaxSpendWei);
    }

    function approveComposeHash(bytes32 composeHash) external onlyOwner {
        _whenMeasurementsMutable();
        if (composeHash == bytes32(0)) revert ZeroHash();
        approvedComposeHashes[composeHash] = true;
        emit ComposeHashApproved(composeHash);
    }

    function revokeComposeHash(bytes32 composeHash) external onlyOwner {
        _whenMeasurementsMutable();
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        approvedComposeHashes[composeHash] = false;
        emit ComposeHashRevoked(composeHash);
    }

    function freezeMeasurements() external onlyOwner {
        _whenMeasurementsMutable();
        measurementsFrozen = true;
        emit MeasurementsFrozenForever();
    }

    function setEmergencyHalt(bool halted) external onlyOwner {
        emergencyHalted = halted;
        emit EmergencyHaltSet(halted);
    }

    function authorizeOperation(
        bytes32 operationId,
        OperationKind kind,
        address requester,
        bytes32 composeHash,
        uint256 amountWei
    ) external onlyOwnerOrManager {
        if (emergencyHalted) revert EmergencyHalted();
        if (operationId == bytes32(0)) revert ZeroHash();
        if (requester == address(0)) revert ZeroAddress();
        // Non-self-approval: the authorizer (owner/manager) cannot also be the
        // requester of the funding operation it authorizes. Agents may request;
        // they must not self-approve. Correct deployment already separates the
        // roles; this enforces it structurally on-chain.
        if (requester == msg.sender) revert SelfApprovalNotAllowed();
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        if (_operations[operationId].requester != address(0)) revert DuplicateOperation();
        _enforceAmount(kind, amountWei);

        _operations[operationId] = OperationRecord({
            kind: kind,
            requester: requester,
            authorizer: msg.sender,
            composeHash: composeHash,
            amountWei: amountWei,
            settled: false,
            success: false,
            receiptHash: bytes32(0)
        });

        emit OperationAuthorized(operationId, kind, requester, msg.sender, composeHash, amountWei);
    }

    function settleOperation(bytes32 operationId, bool success, bytes32 receiptHash)
        external
        onlyOwnerOrManager
    {
        if (receiptHash == bytes32(0)) revert ZeroHash();
        OperationRecord storage record = _operations[operationId];
        if (record.requester == address(0)) revert UnknownOperation();
        if (record.settled) revert AlreadySettled();

        record.settled = true;
        record.success = success;
        record.receiptHash = receiptHash;

        emit OperationSettled(operationId, success, receiptHash);
    }

    function operation(bytes32 operationId) external view returns (OperationRecord memory) {
        OperationRecord memory record = _operations[operationId];
        if (record.requester == address(0)) revert UnknownOperation();
        return record;
    }

    function _whenMeasurementsMutable() internal view {
        if (measurementsFrozen) revert MeasurementsFrozen();
    }

    function _enforceAmount(OperationKind kind, uint256 amountWei) internal view {
        if (kind == OperationKind.AddPaymentMethod) {
            if (amountWei != 0) revert NonZeroAmountForPaymentMethod();
            return;
        }
        if (kind == OperationKind.AddBalance || kind == OperationKind.ManualPrefund) {
            if (amountWei > maxAddBalanceWei) revert AmountExceedsPolicy();
            return;
        }
        if (kind == OperationKind.SpendTinkerCompute) {
            if (amountWei > maxSpendWei) revert AmountExceedsPolicy();
            return;
        }
        revert UnknownOperation();
    }
}
