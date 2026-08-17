// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title TinkerAccountEncumbrance
/// @notice Non-custodial policy and audit surface for a TEE-owned Tinker account.
/// @dev The contract never holds payment cards, Tinker credentials, or user funds.
///      The legacy `Wei` field suffix denotes integer policy units, not ETH or a
///      token balance. Amount limits are per operation, not cumulative account
///      budgets. A fresh deployment is halted until one exact release policy
///      completes a two-day review delay and is permanently frozen. After that
///      point governance may only reduce caps, revoke authority, or halt the
///      release forever. Active operation records can be written only by a
///      manager admitted in that frozen policy, never by the owner.
contract TinkerAccountEncumbrance {
    uint256 public constant RELEASE_POLICY_DELAY = 2 days;
    uint256 public constant MAX_RELEASE_COMPOSES = 16;
    uint256 public constant MAX_RELEASE_MANAGERS = 16;
    /// @notice Hard ceiling for each independently authorized operation.
    /// @dev This is 10e18 unitless policy units. It is neither 10 ETH nor a
    ///      cumulative account budget.
    uint256 public constant MAX_POLICY_UNITS_PER_OPERATION = 10_000_000_000_000_000_000;

    bytes32 public constant COMPOSE_SET_TYPEHASH = keccak256("TinkerComposeSet(bytes32[] composeHashes)");
    bytes32 public constant MANAGER_SET_TYPEHASH = keccak256("TinkerManagerSet(address[] managers)");
    bytes32 public constant ACCOUNT_BINDING_TYPEHASH =
        keccak256("DnaiTinkerAccountBindingV1(uint256 chainId,bytes32 providerNamespace,bytes32 bindingRoot)");
    bytes32 public constant TINKER_PROVIDER_NAMESPACE = keccak256("thinking-machines/tinker");
    bytes32 public constant RELEASE_POLICY_TYPEHASH = keccak256(
        "TinkerReleasePolicy(uint256 chainId,address encumbrance,bytes32 accountCommitment,uint256 maxAddBalanceWei,uint256 maxSpendWei,bytes32 composeRoot,uint256 composeCount,bytes32 managerRoot,uint256 managerCount)"
    );

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
    error NotPendingOwner();
    error NotManager();
    error ZeroAddress();
    error ZeroHash();
    error SelfAddress();
    error NoStateChange();
    error RoleConflict();
    error ReleasePolicyFrozen();
    error ReleasePolicyNotFrozen();
    error ReleasePolicyProposalExists();
    error ReleasePolicyProposalMissing();
    error ReleasePolicyActivationTooEarly(uint256 activatesAt);
    error InvalidComposeSet();
    error InvalidManagerSet();
    error TooManyComposeHashes();
    error TooManyManagers();
    error RiskIncreaseRequiresNewRelease();
    error EmergencyHalted();
    error ComposeHashNotApproved();
    error ManagerNotApproved();
    error AmountExceedsPolicy();
    error DuplicateOperation();
    error UnknownOperation();
    error AlreadySettled();
    error NonZeroAmountForPaymentMethod();
    error SelfApprovalNotAllowed();
    error TimestampOverflow();
    error ZeroFundingPolicyLimit();
    error SpendLimitExceedsAddBalanceLimit();
    error FundingPolicyLimitExceedsMaximum();

    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferCancelled(address indexed currentOwner, address indexed cancelledPendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ManagerSet(address indexed manager, bool allowed);
    event AccountCommitmentUpdated(bytes32 indexed previousCommitment, bytes32 indexed newCommitment);
    event ComposeHashApproved(bytes32 indexed composeHash);
    event ComposeHashRevoked(bytes32 indexed composeHash);
    event EmergencyHaltSet(bool halted);
    event FundingPolicySet(uint256 maxAddBalanceWei, uint256 maxSpendWei);
    event ReleasePolicyProposed(
        bytes32 indexed policyCommitment,
        uint256 activatesAt,
        bytes32 indexed composeRoot,
        bytes32 indexed managerRoot,
        uint256 composeCount,
        uint256 managerCount
    );
    event ReleasePolicyProposalCancelled(bytes32 indexed policyCommitment);
    event ReleasePolicyActivated(
        bytes32 indexed policyCommitment,
        bytes32 indexed composeRoot,
        bytes32 indexed managerRoot,
        uint256 composeCount,
        uint256 managerCount
    );
    event OperationAuthorized(
        bytes32 indexed operationId,
        OperationKind indexed kind,
        address indexed requester,
        address authorizer,
        bytes32 composeHash,
        uint256 amountWei
    );
    event OperationSettled(bytes32 indexed operationId, bool success, bytes32 receiptHash);

    address public owner;
    address public pendingOwner;

    bytes32 public accountCommitment;
    uint256 public maxAddBalanceWei;
    uint256 public maxSpendWei;
    bool public emergencyHalted = true;
    bool public releasePolicyFrozen;

    bytes32 public approvedComposeRoot;
    uint256 public approvedComposeCount;
    bytes32 public managerRoot;
    uint256 public managerCount;

    bytes32 public releasePolicyCommitment;
    uint256 public releaseMaxAddBalanceWei;
    uint256 public releaseMaxSpendWei;
    bytes32 public releaseComposeRoot;
    uint256 public releaseComposeCount;
    bytes32 public releaseManagerRoot;
    uint256 public releaseManagerCount;

    bytes32 public pendingAccountCommitment;
    uint256 public pendingMaxAddBalanceWei;
    uint256 public pendingMaxSpendWei;
    bytes32 public pendingComposeRoot;
    bytes32 public pendingManagerRoot;
    bytes32 public pendingReleasePolicyCommitment;
    uint64 public pendingReleasePolicyActivatesAt;

    mapping(address => bool) public managers;
    mapping(bytes32 => bool) public approvedComposeHashes;
    mapping(address => bool) public pendingManagerApprovals;
    mapping(bytes32 => bool) public pendingComposeApprovals;
    mapping(bytes32 => OperationRecord) private _operations;

    bytes32[] private _approvedComposeHashList;
    address[] private _managerList;
    bytes32[] private _pendingComposeHashList;
    address[] private _pendingManagerList;

    constructor(
        address initialOwner,
        bytes32 initialAccountCommitment,
        bytes32 initialComposeHash,
        uint256 initialMaxAddBalanceWei,
        uint256 initialMaxSpendWei
    ) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (initialOwner == address(this)) revert SelfAddress();
        if (initialAccountCommitment == bytes32(0)) revert ZeroHash();
        _validateFundingPolicy(initialMaxAddBalanceWei, initialMaxSpendWei);

        owner = initialOwner;
        accountCommitment = initialAccountCommitment;
        maxAddBalanceWei = initialMaxAddBalanceWei;
        maxSpendWei = initialMaxSpendWei;

        // A fresh release passes bytes32(0) here. Keeping the optional value
        // preserves compatibility for older local fixtures, but the canonical
        // deployment path is empty and therefore cannot authorize operations
        // before the reviewed release-policy timelock completes.
        if (initialComposeHash != bytes32(0)) {
            approvedComposeHashes[initialComposeHash] = true;
            _approvedComposeHashList.push(initialComposeHash);
        }
        _syncCurrentSetCommitments();

        emit OwnershipTransferred(address(0), initialOwner);
        emit AccountCommitmentUpdated(bytes32(0), initialAccountCommitment);
        if (initialComposeHash != bytes32(0)) emit ComposeHashApproved(initialComposeHash);
        emit FundingPolicySet(initialMaxAddBalanceWei, initialMaxSpendWei);
        emit EmergencyHaltSet(true);
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function _checkOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    /// @notice Begin a two-step governance handoff.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == address(this)) revert SelfAddress();
        if (newOwner == owner || newOwner == pendingOwner) revert NoStateChange();
        if (managers[newOwner] || pendingManagerApprovals[newOwner]) revert RoleConflict();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function cancelOwnershipTransfer() external onlyOwner {
        address proposedOwner = pendingOwner;
        if (proposedOwner == address(0)) revert NotPendingOwner();
        pendingOwner = address(0);
        emit OwnershipTransferCancelled(owner, proposedOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        if (msg.sender == address(this)) revert SelfAddress();
        if (managers[msg.sender] || pendingManagerApprovals[msg.sender]) revert RoleConflict();
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Stage the complete production policy. Arrays must be strictly
    ///         ascending and unique so their commitments are canonical.
    function proposeReleasePolicy(
        bytes32 newAccountCommitment,
        uint256 newMaxAddBalanceWei,
        uint256 newMaxSpendWei,
        bytes32[] calldata composeHashes,
        address[] calldata policyManagers
    ) external onlyOwner {
        if (releasePolicyFrozen) revert ReleasePolicyFrozen();
        if (pendingReleasePolicyActivatesAt != 0) revert ReleasePolicyProposalExists();
        if (newAccountCommitment == bytes32(0)) revert ZeroHash();
        _validateFundingPolicy(newMaxAddBalanceWei, newMaxSpendWei);
        _validateComposeSet(composeHashes);
        _validateManagerSet(policyManagers);

        uint256 activatesAt = block.timestamp + RELEASE_POLICY_DELAY;
        if (activatesAt > type(uint64).max) revert TimestampOverflow();

        bytes32 composeRoot = _computeComposeRoot(composeHashes);
        bytes32 managersRoot = _computeManagerRoot(policyManagers);
        bytes32 policyCommitment = computeReleasePolicyCommitment(
            newAccountCommitment,
            newMaxAddBalanceWei,
            newMaxSpendWei,
            composeRoot,
            composeHashes.length,
            managersRoot,
            policyManagers.length
        );

        pendingAccountCommitment = newAccountCommitment;
        pendingMaxAddBalanceWei = newMaxAddBalanceWei;
        pendingMaxSpendWei = newMaxSpendWei;
        pendingComposeRoot = composeRoot;
        pendingManagerRoot = managersRoot;
        pendingReleasePolicyCommitment = policyCommitment;
        // The explicit upper-bound check above makes this narrowing exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        pendingReleasePolicyActivatesAt = uint64(activatesAt);

        for (uint256 i = 0; i < composeHashes.length; i++) {
            bytes32 composeHash = composeHashes[i];
            _pendingComposeHashList.push(composeHash);
            pendingComposeApprovals[composeHash] = true;
        }
        for (uint256 i = 0; i < policyManagers.length; i++) {
            address manager = policyManagers[i];
            _pendingManagerList.push(manager);
            pendingManagerApprovals[manager] = true;
        }

        emit ReleasePolicyProposed(
            policyCommitment, activatesAt, composeRoot, managersRoot, composeHashes.length, policyManagers.length
        );
    }

    function cancelReleasePolicyProposal() external onlyOwner {
        if (pendingReleasePolicyActivatesAt == 0) revert ReleasePolicyProposalMissing();
        bytes32 policyCommitment = pendingReleasePolicyCommitment;
        _clearPendingReleasePolicy();
        emit ReleasePolicyProposalCancelled(policyCommitment);
    }

    /// @notice Atomically activate the exact staged policy, permanently close all
    ///         authority-increasing paths, and enable bounded operations.
    function activateAndFreezeReleasePolicy() external onlyOwner {
        if (releasePolicyFrozen) revert ReleasePolicyFrozen();
        uint64 activatesAt = pendingReleasePolicyActivatesAt;
        if (activatesAt == 0) revert ReleasePolicyProposalMissing();
        if (block.timestamp < activatesAt) revert ReleasePolicyActivationTooEarly(activatesAt);
        if (pendingOwner != address(0) && pendingManagerApprovals[pendingOwner]) revert RoleConflict();

        _clearCurrentAuthoritySets();
        for (uint256 i = 0; i < _pendingComposeHashList.length; i++) {
            bytes32 composeHash = _pendingComposeHashList[i];
            approvedComposeHashes[composeHash] = true;
            _approvedComposeHashList.push(composeHash);
            emit ComposeHashApproved(composeHash);
        }
        for (uint256 i = 0; i < _pendingManagerList.length; i++) {
            address manager = _pendingManagerList[i];
            managers[manager] = true;
            _managerList.push(manager);
            emit ManagerSet(manager, true);
        }

        bytes32 previousAccountCommitment = accountCommitment;
        accountCommitment = pendingAccountCommitment;
        maxAddBalanceWei = pendingMaxAddBalanceWei;
        maxSpendWei = pendingMaxSpendWei;
        approvedComposeRoot = pendingComposeRoot;
        approvedComposeCount = _pendingComposeHashList.length;
        managerRoot = pendingManagerRoot;
        managerCount = _pendingManagerList.length;

        releasePolicyCommitment = pendingReleasePolicyCommitment;
        releaseMaxAddBalanceWei = maxAddBalanceWei;
        releaseMaxSpendWei = maxSpendWei;
        releaseComposeRoot = approvedComposeRoot;
        releaseComposeCount = approvedComposeCount;
        releaseManagerRoot = managerRoot;
        releaseManagerCount = managerCount;
        releasePolicyFrozen = true;
        emergencyHalted = false;

        bytes32 activatedPolicyCommitment = releasePolicyCommitment;
        bytes32 activatedComposeRoot = approvedComposeRoot;
        bytes32 activatedManagerRoot = managerRoot;
        uint256 activatedComposeCount = approvedComposeCount;
        uint256 activatedManagerCount = managerCount;
        _clearPendingReleasePolicy();

        if (previousAccountCommitment != accountCommitment) {
            emit AccountCommitmentUpdated(previousAccountCommitment, accountCommitment);
        }
        emit FundingPolicySet(maxAddBalanceWei, maxSpendWei);
        emit EmergencyHaltSet(false);
        emit ReleasePolicyActivated(
            activatedPolicyCommitment,
            activatedComposeRoot,
            activatedManagerRoot,
            activatedComposeCount,
            activatedManagerCount
        );
    }

    /// @notice Reduce either per-operation ceiling. Increasing a frozen release
    ///         ceiling requires a separately deployed and reviewed release.
    function reduceFundingPolicy(uint256 newMaxAddBalanceWei, uint256 newMaxSpendWei) external onlyOwner {
        if (newMaxAddBalanceWei > maxAddBalanceWei || newMaxSpendWei > maxSpendWei) {
            revert RiskIncreaseRequiresNewRelease();
        }
        if (newMaxAddBalanceWei == maxAddBalanceWei && newMaxSpendWei == maxSpendWei) revert NoStateChange();
        _validateFundingPolicy(newMaxAddBalanceWei, newMaxSpendWei);
        maxAddBalanceWei = newMaxAddBalanceWei;
        maxSpendWei = newMaxSpendWei;
        emit FundingPolicySet(newMaxAddBalanceWei, newMaxSpendWei);
    }

    /// @notice Revoke a delegated authorizer before or after the release freeze.
    function revokeManager(address manager) external onlyOwner {
        if (!managers[manager]) revert ManagerNotApproved();
        managers[manager] = false;
        _removeManager(manager);
        _syncCurrentSetCommitments();
        emit ManagerSet(manager, false);
    }

    /// @notice Revoke a compose measurement before or after the release freeze.
    function revokeComposeHash(bytes32 composeHash) external onlyOwner {
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        approvedComposeHashes[composeHash] = false;
        _removeComposeHash(composeHash);
        _syncCurrentSetCommitments();
        emit ComposeHashRevoked(composeHash);
    }

    /// @notice One-way emergency stop. A frozen release cannot be resumed in place.
    function setEmergencyHalt(bool halted) external onlyOwner {
        if (!halted) revert RiskIncreaseRequiresNewRelease();
        if (emergencyHalted) revert NoStateChange();
        emergencyHalted = true;
        emit EmergencyHaltSet(true);
    }

    function authorizeOperation(
        bytes32 operationId,
        OperationKind kind,
        address requester,
        bytes32 composeHash,
        uint256 amountWei
    ) external {
        if (!releasePolicyFrozen) revert ReleasePolicyNotFrozen();
        if (emergencyHalted) revert EmergencyHalted();
        if (!managers[msg.sender]) revert NotManager();
        if (operationId == bytes32(0)) revert ZeroHash();
        if (requester == address(0)) revert ZeroAddress();
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

    /// @dev Settlement records remain writable while halted so an already
    ///      authorized external operation can receive its final bounded receipt.
    function settleOperation(bytes32 operationId, bool success, bytes32 receiptHash) external {
        if (!releasePolicyFrozen) revert ReleasePolicyNotFrozen();
        if (!managers[msg.sender]) revert NotManager();
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

    function approvedComposeHashAt(uint256 index) external view returns (bytes32) {
        return _approvedComposeHashList[index];
    }

    function managerAt(uint256 index) external view returns (address) {
        return _managerList[index];
    }

    function pendingComposeCount() external view returns (uint256) {
        return _pendingComposeHashList.length;
    }

    function pendingComposeHashAt(uint256 index) external view returns (bytes32) {
        return _pendingComposeHashList[index];
    }

    function pendingManagerCount() external view returns (uint256) {
        return _pendingManagerList.length;
    }

    function pendingManagerAt(uint256 index) external view returns (address) {
        return _pendingManagerList[index];
    }

    function computeComposeRoot(bytes32[] calldata composeHashes) external pure returns (bytes32) {
        return _computeComposeRoot(composeHashes);
    }

    function computeManagerRoot(address[] calldata policyManagers) external pure returns (bytes32) {
        return _computeManagerRoot(policyManagers);
    }

    function computeReleasePolicyCommitment(
        bytes32 policyAccountCommitment,
        uint256 policyMaxAddBalanceWei,
        uint256 policyMaxSpendWei,
        bytes32 composeRoot,
        uint256 composeCount,
        bytes32 managersRoot,
        uint256 managersCount
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                RELEASE_POLICY_TYPEHASH,
                block.chainid,
                address(this),
                policyAccountCommitment,
                policyMaxAddBalanceWei,
                policyMaxSpendWei,
                composeRoot,
                composeCount,
                managersRoot,
                managersCount
            )
        );
    }

    function _validateComposeSet(bytes32[] calldata composeHashes) internal pure {
        if (composeHashes.length == 0) revert InvalidComposeSet();
        if (composeHashes.length > MAX_RELEASE_COMPOSES) revert TooManyComposeHashes();
        bytes32 previous;
        for (uint256 i = 0; i < composeHashes.length; i++) {
            bytes32 composeHash = composeHashes[i];
            if (composeHash == bytes32(0)) revert InvalidComposeSet();
            if (i != 0 && uint256(composeHash) <= uint256(previous)) revert InvalidComposeSet();
            previous = composeHash;
        }
    }

    function _validateManagerSet(address[] calldata policyManagers) internal view {
        if (policyManagers.length > MAX_RELEASE_MANAGERS) revert TooManyManagers();
        address previous;
        for (uint256 i = 0; i < policyManagers.length; i++) {
            address manager = policyManagers[i];
            if (manager == address(0)) revert InvalidManagerSet();
            if (manager == address(this) || manager == owner || manager == pendingOwner) revert RoleConflict();
            if (i != 0 && uint160(manager) <= uint160(previous)) revert InvalidManagerSet();
            previous = manager;
        }
    }

    function _validateFundingPolicy(uint256 policyMaxAddBalanceWei, uint256 policyMaxSpendWei) internal pure {
        if (policyMaxAddBalanceWei == 0 || policyMaxSpendWei == 0) revert ZeroFundingPolicyLimit();
        if (policyMaxSpendWei > policyMaxAddBalanceWei) revert SpendLimitExceedsAddBalanceLimit();
        if (
            policyMaxAddBalanceWei > MAX_POLICY_UNITS_PER_OPERATION
                || policyMaxSpendWei > MAX_POLICY_UNITS_PER_OPERATION
        ) revert FundingPolicyLimitExceedsMaximum();
    }

    function _computeComposeRoot(bytes32[] calldata composeHashes) internal pure returns (bytes32) {
        return keccak256(abi.encode(COMPOSE_SET_TYPEHASH, composeHashes));
    }

    function _computeManagerRoot(address[] calldata policyManagers) internal pure returns (bytes32) {
        return keccak256(abi.encode(MANAGER_SET_TYPEHASH, policyManagers));
    }

    function _syncCurrentSetCommitments() internal {
        bytes32[] memory composeHashes = _approvedComposeHashList;
        address[] memory policyManagers = _managerList;
        approvedComposeCount = composeHashes.length;
        approvedComposeRoot = keccak256(abi.encode(COMPOSE_SET_TYPEHASH, composeHashes));
        managerCount = policyManagers.length;
        managerRoot = keccak256(abi.encode(MANAGER_SET_TYPEHASH, policyManagers));
    }

    function _clearCurrentAuthoritySets() internal {
        for (uint256 i = 0; i < _approvedComposeHashList.length; i++) {
            approvedComposeHashes[_approvedComposeHashList[i]] = false;
        }
        for (uint256 i = 0; i < _managerList.length; i++) {
            managers[_managerList[i]] = false;
        }
        delete _approvedComposeHashList;
        delete _managerList;
    }

    function _clearPendingReleasePolicy() internal {
        for (uint256 i = 0; i < _pendingComposeHashList.length; i++) {
            pendingComposeApprovals[_pendingComposeHashList[i]] = false;
        }
        for (uint256 i = 0; i < _pendingManagerList.length; i++) {
            pendingManagerApprovals[_pendingManagerList[i]] = false;
        }
        delete _pendingComposeHashList;
        delete _pendingManagerList;
        pendingAccountCommitment = bytes32(0);
        pendingMaxAddBalanceWei = 0;
        pendingMaxSpendWei = 0;
        pendingComposeRoot = bytes32(0);
        pendingManagerRoot = bytes32(0);
        pendingReleasePolicyCommitment = bytes32(0);
        pendingReleasePolicyActivatesAt = 0;
    }

    function _removeComposeHash(bytes32 composeHash) internal {
        uint256 length = _approvedComposeHashList.length;
        for (uint256 i = 0; i < length; i++) {
            if (_approvedComposeHashList[i] != composeHash) continue;
            for (uint256 j = i; j + 1 < length; j++) {
                _approvedComposeHashList[j] = _approvedComposeHashList[j + 1];
            }
            _approvedComposeHashList.pop();
            return;
        }
        revert ComposeHashNotApproved();
    }

    function _removeManager(address manager) internal {
        uint256 length = _managerList.length;
        for (uint256 i = 0; i < length; i++) {
            if (_managerList[i] != manager) continue;
            for (uint256 j = i; j + 1 < length; j++) {
                _managerList[j] = _managerList[j + 1];
            }
            _managerList.pop();
            return;
        }
        revert ManagerNotApproved();
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
