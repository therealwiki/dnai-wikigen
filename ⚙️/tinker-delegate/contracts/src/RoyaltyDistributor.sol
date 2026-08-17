// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC20 surface used for exact-asset royalty settlement.
interface IRoyaltyERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice ERC-1271 contract-wallet signature surface for release authorities.
interface IRoyaltyERC1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);
}

/// @notice Read-only surface of the release-bound monotonic policy anchor.
interface IRoyaltyExecutionPolicyAnchor {
    function writer() external view returns (address);
    function writerReleaseCommitment() external view returns (bytes32);
    function writerRotationsFrozen() external view returns (bool);
    function paused() external view returns (bool);
    function resourceDecisionHead(bytes32 resourceHash) external view returns (bytes32);
    function resourceSequence(bytes32 resourceHash) external view returns (uint256);
    function decisionSequence(bytes32 decisionHash) external view returns (uint256);
}

/// @title RoyaltyDistributor - attested multi-owner pull-payment settlement rail
/// @notice A funder may deposit an exact native or ERC20 royalty only after the
///         exact settlement was authorized by both the release-bound settlement
///         CVM and an independent QVL signer. Each authorization binds the
///         Collaboration room/query/grant/allocation state, exact sorted owner
///         amounts, execution/result/usage/attestation evidence, and the current
///         decision in a frozen ExecutionPolicyAnchor release. Owners withdraw
///         their own accrued balance; neither governance nor a caller can choose
///         entitlement at distribution time.
/// @dev Fresh deployments start paused with no authorities or anchor. Authority
///      rotations and revocation use a two-day proposal/activation cycle. An
///      emergency pause is immediate, but never blocks already-accrued owner
///      withdrawals. ERC20 ingress and egress require exact balance deltas, so
///      fee-on-transfer, rebasing, or dishonest-balance tokens fail closed.
contract RoyaltyDistributor {
    uint256 public constant AUTHORITY_TIMELOCK = 2 days;
    uint256 public constant MAX_AUTHORIZATION_LIFETIME = 10 minutes;
    uint256 public constant MAX_RESERVATION_LIFETIME = 7 days;
    uint256 public constant MAX_RECIPIENTS = 16;
    uint256 private constant ERC1271_GAS_LIMIT = 100_000;
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes4 private constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant NAME_HASH = keccak256("DNAI Royalty Distributor");
    bytes32 public constant VERSION_HASH = keccak256("3");
    bytes32 public constant OWNER_AMOUNTS_TYPEHASH =
        keccak256("RoyaltyOwnerAmounts(address[] owners,uint256[] amounts)");
    bytes32 public constant RELEASE_POLICY_TYPEHASH = keccak256(
        "RoyaltyReleasePolicy(uint256 chainId,address distributor,uint256 authorityNonce,address settlementVerifier,address qvlVerifier,address executionPolicyAnchor,bytes32 anchorWriterReleaseCommitment)"
    );
    bytes32 public constant COLLABORATION_RESOURCE_TYPEHASH = keccak256(
        "RoyaltyCollaborationResource(uint256 chainId,address distributor,bytes32 roomCommitment,bytes32 queryCommitment)"
    );
    bytes32 public constant SETTLEMENT_DECISION_TYPEHASH = keccak256(
        "RoyaltySettlementDecision(uint256 chainId,address distributor,bytes32 settlementId,uint256 settlementNonce,bytes32 fundingReservationId,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,bytes32 resultCommitment,bytes32 usageCommitment,bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,uint256 expiry)"
    );
    bytes32 public constant SETTLEMENT_AUTHORIZATION_TYPEHASH = keccak256(
        "RoyaltySettlementAuthorization(bytes32 settlementId,uint256 settlementNonce,bytes32 fundingReservationId,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,bytes32 resultCommitment,bytes32 usageCommitment,bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,bytes32 anchorDecisionHash,uint256 anchorSequence,uint256 expiry)"
    );
    bytes32 public constant SETTLEMENT_QVL_AUTHORIZATION_TYPEHASH = keccak256(
        "RoyaltySettlementQvlAuthorization(bytes32 settlementId,uint256 settlementNonce,bytes32 fundingReservationId,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,bytes32 resultCommitment,bytes32 usageCommitment,bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,bytes32 anchorDecisionHash,uint256 anchorSequence,uint256 expiry)"
    );
    bytes32 public constant FUNDING_RESERVATION_TYPEHASH = keccak256(
        "RoyaltyFundingReservation(uint256 chainId,address distributor,address sponsor,bytes32 settlementId,uint256 settlementNonce,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,uint256 refundAfter)"
    );

    struct SettlementAuthorization {
        bytes32 settlementId;
        uint256 settlementNonce;
        bytes32 fundingReservationId;
        bytes32 releasePolicyCommitment;
        bytes32 roomCommitment;
        bytes32 roomStateCommitment;
        bytes32 queryCommitment;
        bytes32 grantSetCommitment;
        bytes32 allocationCommitment;
        bytes32 ownersAmountsHash;
        address asset;
        uint256 total;
        bytes32 executionCommitment;
        bytes32 resultCommitment;
        bytes32 usageCommitment;
        bytes32 attestationEvidenceHash;
        bytes32 anchorResourceHash;
        bytes32 anchorDecisionHash;
        uint256 anchorSequence;
        uint256 expiry;
    }

    /// @notice Exact prefunding intent committed before a provider handoff.
    /// @dev Result, usage, and attestation commitments are intentionally absent:
    ///      they do not exist before execution. The later settlement must match
    ///      every field below and additionally carry the release-authorized
    ///      result evidence checked by `SettlementAuthorization`.
    struct FundingReservationRequest {
        bytes32 settlementId;
        uint256 settlementNonce;
        bytes32 releasePolicyCommitment;
        bytes32 roomCommitment;
        bytes32 roomStateCommitment;
        bytes32 queryCommitment;
        bytes32 grantSetCommitment;
        bytes32 allocationCommitment;
        bytes32 ownersAmountsHash;
        address asset;
        uint256 total;
        bytes32 executionCommitment;
        uint64 refundAfter;
    }

    enum FundingReservationStatus {
        None,
        Active,
        Consumed,
        Refunded
    }

    struct FundingReservation {
        bytes32 intentCommitment;
        bytes32 settlementId;
        uint256 settlementNonce;
        bytes32 releasePolicyCommitment;
        bytes32 ownersAmountsHash;
        bytes32 executionCommitment;
        address sponsor;
        address asset;
        uint256 total;
        uint64 refundAfter;
        FundingReservationStatus status;
    }

    /// @notice Compact production-admission view for finalized EIP-1898 reads.
    struct FundingReservationView {
        bool active;
        bool consumed;
        address sponsor;
        address asset;
        uint256 total;
        bytes32 ownerAmountsHash;
        bytes32 releasePolicyCommitment;
        bytes32 executionIntentCommitment;
        uint256 refundAfter;
        uint256 depositedAmount;
    }

    /// @notice Permanent settlement proof fields for one reservation.
    /// @dev A consumed state is written in the same transaction as both replay
    ///      markers and every owner credit. Recomputing `ownerAmountsHash` from
    ///      the expected owners/amounts therefore proves the exact allocation;
    ///      receipt consumers may additionally enumerate `RoyaltyAccrued` logs.
    struct FundingReservationSettlementView {
        bool consumed;
        bool settlementProcessed;
        bool nonceProcessed;
        bytes32 settlementId;
        uint256 settlementNonce;
        address asset;
        uint256 total;
        bytes32 ownerAmountsHash;
    }

    address public owner;
    address public pendingOwner;
    bool public paused = true;

    address public settlementVerifier;
    address public qvlVerifier;
    address public executionPolicyAnchor;
    bytes32 public anchorWriterReleaseCommitment;
    bytes32 public releasePolicyCommitment;
    uint256 public authorityNonce;

    address public pendingSettlementVerifier;
    address public pendingQvlVerifier;
    address public pendingExecutionPolicyAnchor;
    bytes32 public pendingAnchorWriterReleaseCommitment;
    bytes32 public pendingReleasePolicyCommitment;
    uint256 public pendingAuthorityNonce;
    uint64 public pendingAuthorityActivatesAt;
    bool public pendingAuthorityRevocation;

    mapping(address verifier => bool configured) public settlementVerifierEverConfigured;
    mapping(address verifier => bool configured) public qvlVerifierEverConfigured;
    mapping(address writer => bool configured) public anchorWriterEverConfigured;
    mapping(address token => mapping(address ownerAccount => uint256 amount)) public pending;
    mapping(bytes32 settlementId => bool processed) public processedSettlements;
    mapping(uint256 settlementNonce => bool processed) public processedSettlementNonces;
    mapping(address asset => uint256 amount) public totalReserved;
    mapping(address asset => uint256 amount) public totalPending;
    mapping(bytes32 reservationKey => FundingReservation reservation) private _fundingReservations;

    uint256 private _reentrancyLock = 1;

    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferCancelled(address indexed currentOwner, address indexed cancelledPendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PauseSet(bool paused, address indexed caller);
    event AuthorityBindingProposed(
        uint256 indexed authorityNonce,
        address indexed settlementVerifier,
        address indexed qvlVerifier,
        address executionPolicyAnchor,
        bytes32 anchorWriterReleaseCommitment,
        bytes32 releasePolicyCommitment,
        uint256 activatesAt
    );
    event AuthorityRevocationProposed(uint256 indexed authorityNonce, uint256 activatesAt);
    event AuthorityProposalCancelled(uint256 indexed authorityNonce, bool revocation);
    event AuthorityBindingActivated(
        uint256 indexed authorityNonce,
        address indexed settlementVerifier,
        address indexed qvlVerifier,
        address executionPolicyAnchor,
        bytes32 anchorWriterReleaseCommitment,
        bytes32 releasePolicyCommitment
    );
    event AuthorityBindingRevoked(uint256 indexed authorityNonce);
    event RoyaltyDistributed(
        address indexed funder,
        bytes32 indexed settlementId,
        address indexed asset,
        uint256 total,
        uint256 ownerCount,
        uint256 settlementNonce,
        bytes32 anchorDecisionHash,
        uint256 anchorSequence
    );
    event RoyaltyAccrued(address indexed asset, address indexed ownerAccount, uint256 amount);
    event RoyaltyWithdrawn(address indexed ownerAccount, address indexed asset, uint256 amount);
    event FundingReservationCreated(
        bytes32 indexed reservationKey,
        bytes32 indexed settlementId,
        address indexed sponsor,
        address asset,
        uint256 total,
        uint256 settlementNonce,
        bytes32 ownersAmountsHash,
        bytes32 executionCommitment,
        uint256 refundAfter
    );
    event FundingReservationConsumed(
        bytes32 indexed reservationKey,
        bytes32 indexed settlementId,
        address indexed sponsor,
        address asset,
        uint256 total
    );
    event FundingReservationRefunded(
        bytes32 indexed reservationKey,
        bytes32 indexed settlementId,
        address indexed sponsor,
        address asset,
        uint256 total
    );

    error NotOwner();
    error NotPendingOwner();
    error NotEmergencyAuthority();
    error ZeroAddress();
    error ZeroCommitment();
    error RoleConflict();
    error NoStateChange();
    error Paused();
    error ReleaseNotConfigured();
    error ProposalExists();
    error ProposalMissing();
    error TimelockNotElapsed(uint256 activatesAt);
    error TimestampOverflow();
    error InvalidAnchor();
    error AnchorReleaseMismatch();
    error AnchorDecisionMismatch();
    error LengthMismatch();
    error EmptyDistribution();
    error TooManyRecipients();
    error OwnersNotStrictlySorted();
    error ZeroOwner();
    error SelfOwner();
    error ZeroAmount();
    error ZeroSettlementNonce();
    error SettlementExpired();
    error AuthorizationLifetimeTooLong();
    error ReleasePolicyMismatch();
    error OwnersAmountsMismatch();
    error TotalMismatch();
    error ValueMismatch();
    error NothingToWithdraw();
    error TransferFailed();
    error InvalidToken();
    error TokenAmountMismatch();
    error SettlementAlreadyProcessed();
    error SettlementNonceAlreadyProcessed();
    error InvalidSettlementSignature();
    error InvalidQvlSignature();
    error Reentrancy();
    error DirectCustodyDisabled();
    error ReservationExists();
    error ReservationMissing();
    error ReservationNotActive();
    error ReservationExpired();
    error ReservationNotExpired(uint256 refundAfter);
    error ReservationLifetimeInvalid();
    error NotReservationSponsor();
    error SettlementReservationMismatch();
    error SettlementHasActiveReservation();
    error InsolventAsset(address asset, uint256 held, uint256 liability);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (initialOwner == address(this)) revert RoleConflict();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
        emit PauseSet(true, initialOwner);
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    // -- Governance ---------------------------------------------------

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == owner) revert NoStateChange();
        if (_isVerifierRole(newOwner) || _isAnchorWriter(newOwner) || newOwner == address(this)) {
            revert RoleConflict();
        }
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
        if (_isVerifierRole(msg.sender) || _isAnchorWriter(msg.sender) || msg.sender == address(this)) {
            revert RoleConflict();
        }
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Stage an exact settlement-CVM/QVL/anchor release binding.
    /// @dev The binding may initialize or rotate authority. The release-policy
    ///      commitment is derived onchain and includes an incrementing nonce, so
    ///      signatures from an earlier release cannot revive after rotation.
    function proposeAuthorityBinding(
        address newSettlementVerifier,
        address newQvlVerifier,
        address newExecutionPolicyAnchor,
        bytes32 newAnchorWriterReleaseCommitment
    ) external onlyOwner {
        if (pendingAuthorityActivatesAt != 0) revert ProposalExists();
        _validateAuthorityRoles(newSettlementVerifier, newQvlVerifier, newExecutionPolicyAnchor);
        if (newAnchorWriterReleaseCommitment == bytes32(0)) revert ZeroCommitment();
        _validateAnchorRelease(newExecutionPolicyAnchor, newAnchorWriterReleaseCommitment);

        uint256 nextNonce = authorityNonce + 1;
        bytes32 policyCommitment = computeReleasePolicyCommitment(
            nextNonce, newSettlementVerifier, newQvlVerifier, newExecutionPolicyAnchor, newAnchorWriterReleaseCommitment
        );
        uint64 activatesAt = _timelockActivation();
        pendingSettlementVerifier = newSettlementVerifier;
        pendingQvlVerifier = newQvlVerifier;
        pendingExecutionPolicyAnchor = newExecutionPolicyAnchor;
        pendingAnchorWriterReleaseCommitment = newAnchorWriterReleaseCommitment;
        pendingReleasePolicyCommitment = policyCommitment;
        pendingAuthorityNonce = nextNonce;
        pendingAuthorityActivatesAt = activatesAt;
        pendingAuthorityRevocation = false;

        emit AuthorityBindingProposed(
            nextNonce,
            newSettlementVerifier,
            newQvlVerifier,
            newExecutionPolicyAnchor,
            newAnchorWriterReleaseCommitment,
            policyCommitment,
            activatesAt
        );
    }

    /// @notice Stage full authority removal. Emergency pause is separately
    ///         available immediately; this delayed step makes the durable
    ///         release-state change reviewable and prevents accidental removal.
    function proposeAuthorityRevocation() external onlyOwner {
        if (pendingAuthorityActivatesAt != 0) revert ProposalExists();
        if (releasePolicyCommitment == bytes32(0)) revert ReleaseNotConfigured();
        uint256 nextNonce = authorityNonce + 1;
        uint64 activatesAt = _timelockActivation();
        pendingAuthorityNonce = nextNonce;
        pendingAuthorityActivatesAt = activatesAt;
        pendingAuthorityRevocation = true;
        emit AuthorityRevocationProposed(nextNonce, activatesAt);
    }

    function activateAuthorityProposal() external onlyOwner {
        uint64 activatesAt = pendingAuthorityActivatesAt;
        if (activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < activatesAt) revert TimelockNotElapsed(activatesAt);

        uint256 nextNonce = pendingAuthorityNonce;
        if (pendingAuthorityRevocation) {
            settlementVerifier = address(0);
            qvlVerifier = address(0);
            executionPolicyAnchor = address(0);
            anchorWriterReleaseCommitment = bytes32(0);
            releasePolicyCommitment = bytes32(0);
            authorityNonce = nextNonce;
            paused = true;
            _clearAuthorityProposal();
            emit AuthorityBindingRevoked(nextNonce);
            emit PauseSet(true, msg.sender);
            return;
        }

        address newSettlementVerifier = pendingSettlementVerifier;
        address newQvlVerifier = pendingQvlVerifier;
        address newExecutionPolicyAnchor = pendingExecutionPolicyAnchor;
        bytes32 newAnchorRelease = pendingAnchorWriterReleaseCommitment;
        bytes32 newReleasePolicy = pendingReleasePolicyCommitment;
        _validateAuthorityRoles(newSettlementVerifier, newQvlVerifier, newExecutionPolicyAnchor);
        _validateAnchorRelease(newExecutionPolicyAnchor, newAnchorRelease);
        if (
            newReleasePolicy
                != computeReleasePolicyCommitment(
                    nextNonce, newSettlementVerifier, newQvlVerifier, newExecutionPolicyAnchor, newAnchorRelease
                )
        ) revert ReleasePolicyMismatch();

        settlementVerifier = newSettlementVerifier;
        qvlVerifier = newQvlVerifier;
        executionPolicyAnchor = newExecutionPolicyAnchor;
        anchorWriterReleaseCommitment = newAnchorRelease;
        releasePolicyCommitment = newReleasePolicy;
        authorityNonce = nextNonce;
        settlementVerifierEverConfigured[newSettlementVerifier] = true;
        qvlVerifierEverConfigured[newQvlVerifier] = true;
        anchorWriterEverConfigured[IRoyaltyExecutionPolicyAnchor(newExecutionPolicyAnchor).writer()] = true;
        _clearAuthorityProposal();
        emit AuthorityBindingActivated(
            nextNonce,
            newSettlementVerifier,
            newQvlVerifier,
            newExecutionPolicyAnchor,
            newAnchorRelease,
            newReleasePolicy
        );
    }

    function cancelAuthorityProposal() external onlyOwner {
        if (pendingAuthorityActivatesAt == 0) revert ProposalMissing();
        uint256 proposedNonce = pendingAuthorityNonce;
        bool revocation = pendingAuthorityRevocation;
        _clearAuthorityProposal();
        emit AuthorityProposalCancelled(proposedNonce, revocation);
    }

    /// @notice Immediate stop by governance or either active release signer;
    ///         only governance may resume after all release checks pass again.
    function setPaused(bool newPaused) external {
        if (newPaused) {
            if (msg.sender != owner && msg.sender != settlementVerifier && msg.sender != qvlVerifier) {
                revert NotEmergencyAuthority();
            }
        } else {
            if (msg.sender != owner) revert NotOwner();
            _requireActiveRelease();
        }
        if (paused == newPaused) revert NoStateChange();
        paused = newPaused;
        emit PauseSet(newPaused, msg.sender);
    }

    // -- Intent-keyed prefunding -------------------------------------

    /// @notice Escrow exact native funding for one future settlement intent.
    /// @dev The sponsor is authenticated by the transaction sender. Settlement
    ///      and QVL signatures are deliberately deferred until consumption,
    ///      after result/usage/attestation commitments exist.
    function reserveNative(FundingReservationRequest calldata request)
        external
        payable
        nonReentrant
        returns (bytes32 reservationId)
    {
        if (request.asset != address(0)) revert InvalidToken();
        if (msg.value != request.total) revert ValueMismatch();
        reservationId = _validateReservationRequest(msg.sender, request);
        _recordReservation(reservationId, msg.sender, request);
        _assertSolvent(address(0));
    }

    /// @notice Escrow an exact ERC20 amount for one future settlement intent.
    /// @dev Exact balance-delta validation rejects fee-on-transfer, rebasing,
    ///      phantom, and otherwise non-exact token behavior.
    function reserveERC20(FundingReservationRequest calldata request)
        external
        nonReentrant
        returns (bytes32 reservationId)
    {
        address token = request.asset;
        _requireToken(token);
        reservationId = _validateReservationRequest(msg.sender, request);
        uint256 balanceBefore = _tokenBalance(token, address(this));
        _safeTransferFrom(token, msg.sender, address(this), request.total);
        uint256 balanceAfter = _tokenBalance(token, address(this));
        if (balanceAfter < balanceBefore || balanceAfter - balanceBefore != request.total) {
            revert TokenAmountMismatch();
        }
        _recordReservation(reservationId, msg.sender, request);
        _assertSolvent(token);
    }

    /// @notice Consume escrowed funding using the exact dual-signed settlement.
    /// @dev Anyone may relay the signed settlement, but only the recorded
    ///      sponsor's already-held funds are consumed. At `refundAfter` the
    ///      refund branch wins; settlement is accepted only strictly before it.
    function settleReserved(
        bytes32 reservationId,
        SettlementAuthorization calldata authorization,
        address[] calldata owners,
        uint256[] calldata amounts,
        bytes calldata settlementSignature,
        bytes calldata qvlSignature
    ) external nonReentrant {
        FundingReservation storage reservation = _fundingReservations[reservationId];
        if (reservation.status == FundingReservationStatus.None) revert ReservationMissing();
        if (reservation.status != FundingReservationStatus.Active) revert ReservationNotActive();
        if (block.timestamp >= reservation.refundAfter) revert ReservationExpired();
        if (
            authorization.fundingReservationId != reservationId || authorization.expiry > reservation.refundAfter
                || _reservationIdFromAuthorization(reservation.sponsor, authorization, reservation.refundAfter)
                    != reservationId
        ) {
            revert SettlementReservationMismatch();
        }

        _validateSettlement(authorization, owners, amounts, settlementSignature, qvlSignature);
        reservation.status = FundingReservationStatus.Consumed;
        totalReserved[reservation.asset] -= reservation.total;
        _creditSettlement(authorization, owners, amounts, reservation.sponsor);
        _assertSolvent(reservation.asset);
        emit FundingReservationConsumed(
            reservationId, reservation.settlementId, reservation.sponsor, reservation.asset, reservation.total
        );
    }

    /// @notice Return an unconsumed reservation to its sponsor after expiry.
    /// @dev This remains available while paused or after authority revocation.
    function refundFundingReservation(bytes32 reservationId) external nonReentrant {
        FundingReservation storage reservation = _fundingReservations[reservationId];
        if (reservation.status == FundingReservationStatus.None) revert ReservationMissing();
        if (reservation.status != FundingReservationStatus.Active) revert ReservationNotActive();
        if (msg.sender != reservation.sponsor) revert NotReservationSponsor();
        if (block.timestamp < reservation.refundAfter) {
            revert ReservationNotExpired(reservation.refundAfter);
        }

        reservation.status = FundingReservationStatus.Refunded;
        totalReserved[reservation.asset] -= reservation.total;
        if (reservation.asset == address(0)) {
            (bool ok,) = reservation.sponsor.call{value: reservation.total}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(reservation.asset, reservation.sponsor, reservation.total);
        }
        _assertSolvent(reservation.asset);
        emit FundingReservationRefunded(
            reservationId, reservation.settlementId, reservation.sponsor, reservation.asset, reservation.total
        );
    }

    // -- Authorized settlement --------------------------------------

    function distributeNative(
        SettlementAuthorization calldata authorization,
        address[] calldata owners,
        uint256[] calldata amounts,
        bytes calldata settlementSignature,
        bytes calldata qvlSignature
    ) external payable nonReentrant {
        if (authorization.asset != address(0)) revert InvalidToken();
        if (authorization.fundingReservationId != bytes32(0)) revert SettlementReservationMismatch();
        if (msg.value != authorization.total) revert ValueMismatch();
        _validateSettlement(authorization, owners, amounts, settlementSignature, qvlSignature);
        _creditSettlement(authorization, owners, amounts, msg.sender);
        _assertSolvent(address(0));
    }

    function distributeERC20(
        SettlementAuthorization calldata authorization,
        address[] calldata owners,
        uint256[] calldata amounts,
        bytes calldata settlementSignature,
        bytes calldata qvlSignature
    ) external nonReentrant {
        address token = authorization.asset;
        if (authorization.fundingReservationId != bytes32(0)) revert SettlementReservationMismatch();
        _requireToken(token);
        _validateSettlement(authorization, owners, amounts, settlementSignature, qvlSignature);
        uint256 balanceBefore = _tokenBalance(token, address(this));
        _safeTransferFrom(token, msg.sender, address(this), authorization.total);
        uint256 balanceAfter = _tokenBalance(token, address(this));
        if (balanceAfter < balanceBefore || balanceAfter - balanceBefore != authorization.total) {
            revert TokenAmountMismatch();
        }
        _creditSettlement(authorization, owners, amounts, msg.sender);
        _assertSolvent(token);
    }

    /// @notice Withdraw claimable native royalties. This remains available
    ///         while settlement authority is paused or revoked.
    function withdraw() external nonReentrant {
        _withdraw(address(0));
    }

    /// @notice Withdraw claimable royalties in an exact ERC20 asset.
    function withdraw(address token) external nonReentrant {
        _withdraw(token);
    }

    // -- Canonical commitments and compatibility reads ---------------

    /// @notice Deterministic reservation key for an exact sponsor and intent.
    function fundingReservationId(address sponsor, FundingReservationRequest calldata request)
        public
        view
        returns (bytes32)
    {
        bytes32[17] memory words;
        words[0] = FUNDING_RESERVATION_TYPEHASH;
        words[1] = bytes32(block.chainid);
        words[2] = _addressWord(address(this));
        words[3] = _addressWord(sponsor);
        words[4] = request.settlementId;
        words[5] = bytes32(request.settlementNonce);
        words[6] = request.releasePolicyCommitment;
        words[7] = request.roomCommitment;
        words[8] = request.roomStateCommitment;
        words[9] = request.queryCommitment;
        words[10] = request.grantSetCommitment;
        words[11] = request.allocationCommitment;
        words[12] = request.ownersAmountsHash;
        words[13] = _addressWord(request.asset);
        words[14] = bytes32(request.total);
        words[15] = request.executionCommitment;
        words[16] = bytes32(uint256(request.refundAfter));
        return keccak256(abi.encodePacked(words));
    }

    /// @notice Static reservation read intended for EIP-1898 finalized calls.
    /// @dev `active` includes the strict time boundary; status remains `Active`
    ///      after expiry until the sponsor records the permanent refund state.
    function fundingReservationState(bytes32 reservationId)
        external
        view
        returns (FundingReservation memory reservation, bool active)
    {
        reservation = _fundingReservations[reservationId];
        active = reservation.status == FundingReservationStatus.Active && block.timestamp < reservation.refundAfter
            && _assetIsSolvent(reservation.asset);
    }

    /// @notice Exact view consumed by the Collaboration production worker.
    /// @dev Balance and allowance reads are diagnostic only and MUST NOT replace
    ///      this finalized, intent-keyed active-reservation check.
    function collaborationFundingReservation(bytes32 reservationId)
        external
        view
        returns (FundingReservationView memory viewState)
    {
        FundingReservation storage reservation = _fundingReservations[reservationId];
        bool storageActive = reservation.status == FundingReservationStatus.Active;
        bool solvent = !storageActive || _assetIsSolvent(reservation.asset);
        viewState = FundingReservationView({
            active: storageActive && block.timestamp < reservation.refundAfter && solvent,
            consumed: reservation.status == FundingReservationStatus.Consumed,
            sponsor: reservation.sponsor,
            asset: reservation.asset,
            total: reservation.total,
            ownerAmountsHash: reservation.ownersAmountsHash,
            releasePolicyCommitment: reservation.releasePolicyCommitment,
            executionIntentCommitment: reservation.executionCommitment,
            refundAfter: reservation.refundAfter,
            depositedAmount: storageActive && solvent ? reservation.total : 0
        });
    }

    /// @notice Finalized reconciliation view for a reserved settlement.
    /// @dev Read at one finalized EIP-1898 block. The tuple is entirely static
    ///      so production workers can reject missing/truncated RPC responses.
    function fundingReservationSettlementState(bytes32 reservationId)
        external
        view
        returns (FundingReservationSettlementView memory viewState)
    {
        FundingReservation storage reservation = _fundingReservations[reservationId];
        viewState = FundingReservationSettlementView({
            consumed: reservation.status == FundingReservationStatus.Consumed,
            settlementProcessed: processedSettlements[reservation.settlementId],
            nonceProcessed: processedSettlementNonces[reservation.settlementNonce],
            settlementId: reservation.settlementId,
            settlementNonce: reservation.settlementNonce,
            asset: reservation.asset,
            total: reservation.total,
            ownerAmountsHash: reservation.ownersAmountsHash
        });
    }

    /// @notice Diagnostic conservation read. Production admission must use an
    ///         exact active reservation, never this balance aggregate alone.
    function assetLiabilityState(address asset)
        external
        view
        returns (uint256 reserved, uint256 claimable, uint256 held, bool solvent)
    {
        reserved = totalReserved[asset];
        claimable = totalPending[asset];
        held = asset == address(0) ? address(this).balance : _tokenBalance(asset, address(this));
        solvent = held >= reserved + claimable;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function computeOwnerAmountsHash(address[] calldata owners, uint256[] calldata amounts)
        public
        pure
        returns (bytes32)
    {
        // EIP-712 array members are hashed from the concatenated 32-byte
        // encoding of each element, then those two array hashes are encoded in
        // the parent struct. `abi.encodePacked` pads array elements to 32 bytes.
        return keccak256(
            abi.encode(
                OWNER_AMOUNTS_TYPEHASH, keccak256(abi.encodePacked(owners)), keccak256(abi.encodePacked(amounts))
            )
        );
    }

    function computeReleasePolicyCommitment(
        uint256 policyAuthorityNonce,
        address policySettlementVerifier,
        address policyQvlVerifier,
        address policyExecutionPolicyAnchor,
        bytes32 policyAnchorWriterReleaseCommitment
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                RELEASE_POLICY_TYPEHASH,
                block.chainid,
                address(this),
                policyAuthorityNonce,
                policySettlementVerifier,
                policyQvlVerifier,
                policyExecutionPolicyAnchor,
                policyAnchorWriterReleaseCommitment
            )
        );
    }

    function collaborationResourceHash(bytes32 roomCommitment, bytes32 queryCommitment) public view returns (bytes32) {
        return keccak256(
            abi.encode(COLLABORATION_RESOURCE_TYPEHASH, block.chainid, address(this), roomCommitment, queryCommitment)
        );
    }

    /// @notice Canonical opaque decision that must be the current anchor head.
    /// @dev The decision intentionally excludes its own hash and sequence. The
    ///      anchor writer first anchors this value, then both release signers bind
    ///      the returned decision hash and sequence in their EIP-712 signatures.
    function settlementDecisionHash(SettlementAuthorization calldata authorization) public view returns (bytes32) {
        bytes32[21] memory words;
        words[0] = SETTLEMENT_DECISION_TYPEHASH;
        words[1] = bytes32(block.chainid);
        words[2] = _addressWord(address(this));
        words[3] = authorization.settlementId;
        words[4] = bytes32(authorization.settlementNonce);
        words[5] = authorization.fundingReservationId;
        words[6] = authorization.releasePolicyCommitment;
        words[7] = authorization.roomCommitment;
        words[8] = authorization.roomStateCommitment;
        words[9] = authorization.queryCommitment;
        words[10] = authorization.grantSetCommitment;
        words[11] = authorization.allocationCommitment;
        words[12] = authorization.ownersAmountsHash;
        words[13] = _addressWord(authorization.asset);
        words[14] = bytes32(authorization.total);
        words[15] = authorization.executionCommitment;
        words[16] = authorization.resultCommitment;
        words[17] = authorization.usageCommitment;
        words[18] = authorization.attestationEvidenceHash;
        words[19] = authorization.anchorResourceHash;
        words[20] = bytes32(authorization.expiry);
        return keccak256(abi.encodePacked(words));
    }

    function settlementAuthorizationDigest(SettlementAuthorization calldata authorization)
        public
        view
        returns (bytes32)
    {
        return _authorizationDigest(SETTLEMENT_AUTHORIZATION_TYPEHASH, authorization);
    }

    function settlementQvlAuthorizationDigest(SettlementAuthorization calldata authorization)
        public
        view
        returns (bytes32)
    {
        return _authorizationDigest(SETTLEMENT_QVL_AUTHORIZATION_TYPEHASH, authorization);
    }

    // -- Internal validation/accounting -------------------------------

    function _validateSettlement(
        SettlementAuthorization calldata authorization,
        address[] calldata owners,
        uint256[] calldata amounts,
        bytes calldata settlementSignature,
        bytes calldata qvlSignature
    ) internal view {
        if (paused) revert Paused();
        _requireActiveRelease();
        _validateAuthorizationFields(authorization);
        if (authorization.releasePolicyCommitment != releasePolicyCommitment) revert ReleasePolicyMismatch();
        if (
            authorization.anchorResourceHash
                != collaborationResourceHash(authorization.roomCommitment, authorization.queryCommitment)
        ) {
            revert AnchorDecisionMismatch();
        }
        if (authorization.anchorDecisionHash != settlementDecisionHash(authorization)) revert AnchorDecisionMismatch();
        _validateCurrentAnchorDecision(authorization);
        if (processedSettlements[authorization.settlementId]) revert SettlementAlreadyProcessed();
        if (processedSettlementNonces[authorization.settlementNonce]) revert SettlementNonceAlreadyProcessed();

        bytes32 ownerAmountsHash = computeOwnerAmountsHash(owners, amounts);
        if (ownerAmountsHash != authorization.ownersAmountsHash) revert OwnersAmountsMismatch();
        uint256 total = _validateRecipientsAndTotal(owners, amounts);
        if (total != authorization.total) revert TotalMismatch();

        if (!_isValidSigner(settlementVerifier, settlementAuthorizationDigest(authorization), settlementSignature)) {
            revert InvalidSettlementSignature();
        }
        if (!_isValidSigner(qvlVerifier, settlementQvlAuthorizationDigest(authorization), qvlSignature)) {
            revert InvalidQvlSignature();
        }
    }

    function _creditSettlement(
        SettlementAuthorization calldata authorization,
        address[] calldata owners,
        uint256[] calldata amounts,
        address funder
    ) internal {
        processedSettlements[authorization.settlementId] = true;
        processedSettlementNonces[authorization.settlementNonce] = true;
        totalPending[authorization.asset] += authorization.total;
        for (uint256 i = 0; i < owners.length; i++) {
            address ownerAccount = owners[i];
            uint256 amount = amounts[i];
            pending[authorization.asset][ownerAccount] += amount;
            emit RoyaltyAccrued(authorization.asset, ownerAccount, amount);
        }
        emit RoyaltyDistributed(
            funder,
            authorization.settlementId,
            authorization.asset,
            authorization.total,
            owners.length,
            authorization.settlementNonce,
            authorization.anchorDecisionHash,
            authorization.anchorSequence
        );
    }

    function _validateReservationRequest(address sponsor, FundingReservationRequest calldata request)
        internal
        view
        returns (bytes32 reservationId)
    {
        if (paused) revert Paused();
        _requireActiveRelease();
        if (pendingAuthorityActivatesAt != 0) revert ProposalExists();
        if (sponsor == address(0) || sponsor == address(this)) revert RoleConflict();
        if (
            request.settlementId == bytes32(0) || request.releasePolicyCommitment == bytes32(0)
                || request.roomCommitment == bytes32(0) || request.roomStateCommitment == bytes32(0)
                || request.queryCommitment == bytes32(0) || request.grantSetCommitment == bytes32(0)
                || request.allocationCommitment == bytes32(0) || request.ownersAmountsHash == bytes32(0)
                || request.executionCommitment == bytes32(0)
        ) revert ZeroCommitment();
        if (request.settlementNonce == 0) revert ZeroSettlementNonce();
        if (request.total == 0) revert ZeroAmount();
        if (request.releasePolicyCommitment != releasePolicyCommitment) revert ReleasePolicyMismatch();
        if (processedSettlements[request.settlementId]) revert SettlementAlreadyProcessed();
        if (processedSettlementNonces[request.settlementNonce]) revert SettlementNonceAlreadyProcessed();
        if (
            request.refundAfter <= block.timestamp
                || uint256(request.refundAfter) - block.timestamp > MAX_RESERVATION_LIFETIME
        ) revert ReservationLifetimeInvalid();
        reservationId = fundingReservationId(sponsor, request);
        if (_fundingReservations[reservationId].status != FundingReservationStatus.None) {
            revert ReservationExists();
        }
    }

    function _recordReservation(bytes32 reservationId, address sponsor, FundingReservationRequest calldata request)
        internal
    {
        _fundingReservations[reservationId] = FundingReservation({
            intentCommitment: reservationId,
            settlementId: request.settlementId,
            settlementNonce: request.settlementNonce,
            releasePolicyCommitment: request.releasePolicyCommitment,
            ownersAmountsHash: request.ownersAmountsHash,
            executionCommitment: request.executionCommitment,
            sponsor: sponsor,
            asset: request.asset,
            total: request.total,
            refundAfter: request.refundAfter,
            status: FundingReservationStatus.Active
        });
        totalReserved[request.asset] += request.total;
        emit FundingReservationCreated(
            reservationId,
            request.settlementId,
            sponsor,
            request.asset,
            request.total,
            request.settlementNonce,
            request.ownersAmountsHash,
            request.executionCommitment,
            request.refundAfter
        );
    }

    function _reservationIdFromAuthorization(
        address sponsor,
        SettlementAuthorization calldata authorization,
        uint64 refundAfter
    ) internal view returns (bytes32) {
        bytes32[17] memory words;
        words[0] = FUNDING_RESERVATION_TYPEHASH;
        words[1] = bytes32(block.chainid);
        words[2] = _addressWord(address(this));
        words[3] = _addressWord(sponsor);
        words[4] = authorization.settlementId;
        words[5] = bytes32(authorization.settlementNonce);
        words[6] = authorization.releasePolicyCommitment;
        words[7] = authorization.roomCommitment;
        words[8] = authorization.roomStateCommitment;
        words[9] = authorization.queryCommitment;
        words[10] = authorization.grantSetCommitment;
        words[11] = authorization.allocationCommitment;
        words[12] = authorization.ownersAmountsHash;
        words[13] = _addressWord(authorization.asset);
        words[14] = bytes32(authorization.total);
        words[15] = authorization.executionCommitment;
        words[16] = bytes32(uint256(refundAfter));
        return keccak256(abi.encodePacked(words));
    }

    function _validateAuthorizationFields(SettlementAuthorization calldata authorization) internal view {
        if (
            authorization.settlementId == bytes32(0) || authorization.roomCommitment == bytes32(0)
                || authorization.roomStateCommitment == bytes32(0) || authorization.queryCommitment == bytes32(0)
                || authorization.grantSetCommitment == bytes32(0) || authorization.allocationCommitment == bytes32(0)
                || authorization.ownersAmountsHash == bytes32(0) || authorization.executionCommitment == bytes32(0)
                || authorization.resultCommitment == bytes32(0) || authorization.usageCommitment == bytes32(0)
                || authorization.attestationEvidenceHash == bytes32(0) || authorization.anchorResourceHash == bytes32(0)
                || authorization.anchorDecisionHash == bytes32(0)
        ) revert ZeroCommitment();
        if (authorization.settlementNonce == 0) revert ZeroSettlementNonce();
        if (authorization.total == 0) revert ZeroAmount();
        if (authorization.anchorSequence == 0) revert AnchorDecisionMismatch();
        if (block.timestamp > authorization.expiry) revert SettlementExpired();
        if (authorization.expiry - block.timestamp > MAX_AUTHORIZATION_LIFETIME) {
            revert AuthorizationLifetimeTooLong();
        }
    }

    function _validateRecipientsAndTotal(address[] calldata owners, uint256[] calldata amounts)
        internal
        view
        returns (uint256 total)
    {
        uint256 count = owners.length;
        if (count != amounts.length) revert LengthMismatch();
        if (count == 0) revert EmptyDistribution();
        if (count > MAX_RECIPIENTS) revert TooManyRecipients();
        address previous;
        for (uint256 i = 0; i < count; i++) {
            address ownerAccount = owners[i];
            uint256 amount = amounts[i];
            if (ownerAccount == address(0)) revert ZeroOwner();
            if (ownerAccount == address(this)) revert SelfOwner();
            if (i != 0 && ownerAccount <= previous) revert OwnersNotStrictlySorted();
            if (amount == 0) revert ZeroAmount();
            previous = ownerAccount;
            total += amount;
        }
    }

    function _validateCurrentAnchorDecision(SettlementAuthorization calldata authorization) internal view {
        IRoyaltyExecutionPolicyAnchor anchor = IRoyaltyExecutionPolicyAnchor(executionPolicyAnchor);
        if (
            anchor.decisionSequence(authorization.anchorDecisionHash) != authorization.anchorSequence
                || anchor.resourceSequence(authorization.anchorResourceHash) != authorization.anchorSequence
                || anchor.resourceDecisionHead(authorization.anchorResourceHash) != authorization.anchorDecisionHash
        ) revert AnchorDecisionMismatch();
    }

    function _requireActiveRelease() internal view {
        if (
            settlementVerifier == address(0) || qvlVerifier == address(0) || settlementVerifier == qvlVerifier
                || executionPolicyAnchor == address(0) || releasePolicyCommitment == bytes32(0)
                || anchorWriterReleaseCommitment == bytes32(0)
        ) revert ReleaseNotConfigured();
        _validateAnchorRelease(executionPolicyAnchor, anchorWriterReleaseCommitment);
        if (
            releasePolicyCommitment
                != computeReleasePolicyCommitment(
                    authorityNonce,
                    settlementVerifier,
                    qvlVerifier,
                    executionPolicyAnchor,
                    anchorWriterReleaseCommitment
                )
        ) revert ReleasePolicyMismatch();
    }

    function _validateAuthorityRoles(address candidateSettlement, address candidateQvl, address candidateAnchor)
        internal
        view
    {
        if (candidateSettlement == address(0) || candidateQvl == address(0) || candidateAnchor == address(0)) {
            revert ZeroAddress();
        }
        if (
            candidateSettlement == candidateQvl || candidateSettlement == owner || candidateSettlement == pendingOwner
                || candidateSettlement == address(this) || candidateQvl == owner || candidateQvl == pendingOwner
                || candidateQvl == address(this) || candidateAnchor == address(this) || candidateAnchor == owner
                || candidateAnchor == pendingOwner || candidateAnchor == candidateSettlement
                || candidateAnchor == candidateQvl || qvlVerifierEverConfigured[candidateSettlement]
                || settlementVerifierEverConfigured[candidateQvl] || anchorWriterEverConfigured[candidateSettlement]
                || anchorWriterEverConfigured[candidateQvl]
        ) revert RoleConflict();
        if (candidateAnchor.code.length == 0) revert InvalidAnchor();
        address anchorWriter = IRoyaltyExecutionPolicyAnchor(candidateAnchor).writer();
        if (anchorWriter == address(0)) revert InvalidAnchor();
        if (
            anchorWriter == address(this) || anchorWriter == owner || anchorWriter == pendingOwner
                || anchorWriter == candidateSettlement || anchorWriter == candidateQvl
                || anchorWriter == candidateAnchor || settlementVerifierEverConfigured[anchorWriter]
                || qvlVerifierEverConfigured[anchorWriter]
        ) revert RoleConflict();
    }

    function _validateAnchorRelease(address candidateAnchor, bytes32 expectedWriterRelease) internal view {
        if (candidateAnchor == address(0) || candidateAnchor.code.length == 0) revert InvalidAnchor();
        IRoyaltyExecutionPolicyAnchor anchor = IRoyaltyExecutionPolicyAnchor(candidateAnchor);
        if (!anchor.writerRotationsFrozen() || anchor.paused() || anchor.writer() == address(0)) {
            revert InvalidAnchor();
        }
        if (anchor.writerReleaseCommitment() != expectedWriterRelease) revert AnchorReleaseMismatch();
    }

    function _isVerifierRole(address account) internal view returns (bool) {
        return account == settlementVerifier || account == qvlVerifier || account == pendingSettlementVerifier
            || account == pendingQvlVerifier || settlementVerifierEverConfigured[account]
            || qvlVerifierEverConfigured[account];
    }

    function _isAnchorWriter(address account) internal view returns (bool) {
        if (anchorWriterEverConfigured[account]) return true;
        if (executionPolicyAnchor != address(0)) {
            if (IRoyaltyExecutionPolicyAnchor(executionPolicyAnchor).writer() == account) return true;
        }
        if (pendingExecutionPolicyAnchor != address(0)) {
            if (IRoyaltyExecutionPolicyAnchor(pendingExecutionPolicyAnchor).writer() == account) return true;
        }
        return false;
    }

    function _clearAuthorityProposal() internal {
        pendingSettlementVerifier = address(0);
        pendingQvlVerifier = address(0);
        pendingExecutionPolicyAnchor = address(0);
        pendingAnchorWriterReleaseCommitment = bytes32(0);
        pendingReleasePolicyCommitment = bytes32(0);
        pendingAuthorityNonce = 0;
        pendingAuthorityActivatesAt = 0;
        pendingAuthorityRevocation = false;
    }

    function _authorizationDigest(bytes32 authorizationTypehash, SettlementAuthorization calldata authorization)
        internal
        view
        returns (bytes32)
    {
        bytes32[21] memory words;
        words[0] = authorizationTypehash;
        words[1] = authorization.settlementId;
        words[2] = bytes32(authorization.settlementNonce);
        words[3] = authorization.fundingReservationId;
        words[4] = authorization.releasePolicyCommitment;
        words[5] = authorization.roomCommitment;
        words[6] = authorization.roomStateCommitment;
        words[7] = authorization.queryCommitment;
        words[8] = authorization.grantSetCommitment;
        words[9] = authorization.allocationCommitment;
        words[10] = authorization.ownersAmountsHash;
        words[11] = _addressWord(authorization.asset);
        words[12] = bytes32(authorization.total);
        words[13] = authorization.executionCommitment;
        words[14] = authorization.resultCommitment;
        words[15] = authorization.usageCommitment;
        words[16] = authorization.attestationEvidenceHash;
        words[17] = authorization.anchorResourceHash;
        words[18] = authorization.anchorDecisionHash;
        words[19] = bytes32(authorization.anchorSequence);
        words[20] = bytes32(authorization.expiry);
        bytes32 structHash = keccak256(abi.encodePacked(words));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _addressWord(address account) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(account)));
    }

    function _isValidSigner(address signer, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        if (signer.code.length == 0) return _recover(digest, signature) == signer;
        (bool ok, bytes memory result) = signer.staticcall{gas: ERC1271_GAS_LIMIT}(
            abi.encodeWithSelector(IRoyaltyERC1271.isValidSignature.selector, digest, signature)
        );
        return ok && result.length >= 32 && abi.decode(result, (bytes4)) == ERC1271_MAGIC_VALUE;
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v != 27 && v != 28) return address(0);
        if (uint256(r) == 0 || uint256(s) == 0 || uint256(s) > SECP256K1_HALF_ORDER) return address(0);
        signer = ecrecover(digest, v, r, s);
    }

    function _withdraw(address token) internal {
        uint256 amount = pending[token][msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        pending[token][msg.sender] = 0;
        totalPending[token] -= amount;
        if (token == address(0)) {
            (bool ok,) = msg.sender.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(token, msg.sender, amount);
        }
        _assertSolvent(token);
        emit RoyaltyWithdrawn(msg.sender, token, amount);
    }

    function _assertSolvent(address asset) internal view {
        uint256 held = _assetHeld(asset);
        uint256 liability = totalReserved[asset] + totalPending[asset];
        if (held < liability) revert InsolventAsset(asset, held, liability);
    }

    function _assetIsSolvent(address asset) internal view returns (bool) {
        return _assetHeld(asset) >= totalReserved[asset] + totalPending[asset];
    }

    function _assetHeld(address asset) internal view returns (uint256) {
        return asset == address(0) ? address(this).balance : _tokenBalance(asset, address(this));
    }

    function _safeTransfer(address token, address to, uint256 amount) internal {
        _requireToken(token);
        uint256 senderBefore = _tokenBalance(token, address(this));
        uint256 recipientBefore = _tokenBalance(token, to);
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(IRoyaltyERC20.transfer.selector, to, amount));
        if (!ok || (data.length != 0 && (data.length < 32 || !abi.decode(data, (bool))))) revert TransferFailed();
        uint256 senderAfter = _tokenBalance(token, address(this));
        uint256 recipientAfter = _tokenBalance(token, to);
        if (
            senderAfter > senderBefore || senderBefore - senderAfter != amount || recipientAfter < recipientBefore
                || recipientAfter - recipientBefore != amount
        ) revert TokenAmountMismatch();
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(IRoyaltyERC20.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && (data.length < 32 || !abi.decode(data, (bool))))) revert TransferFailed();
    }

    function _tokenBalance(address token, address account) internal view returns (uint256 balance) {
        _requireToken(token);
        (bool ok, bytes memory data) =
            token.staticcall(abi.encodeWithSelector(IRoyaltyERC20.balanceOf.selector, account));
        if (!ok || data.length < 32) revert InvalidToken();
        balance = abi.decode(data, (uint256));
    }

    function _requireToken(address token) internal view {
        if (token == address(0) || token.code.length == 0) revert InvalidToken();
    }

    function _timelockActivation() internal view returns (uint64) {
        uint256 activation = block.timestamp + AUTHORITY_TIMELOCK;
        if (activation > type(uint64).max) revert TimestampOverflow();
        // The explicit upper-bound check above makes this narrowing exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(activation);
    }

    function _checkOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _nonReentrantBefore() internal {
        if (_reentrancyLock != 1) revert Reentrancy();
        _reentrancyLock = 2;
    }

    function _nonReentrantAfter() internal {
        _reentrancyLock = 1;
    }

    receive() external payable {
        revert DirectCustodyDisabled();
    }

    fallback() external payable {
        revert DirectCustodyDisabled();
    }
}
