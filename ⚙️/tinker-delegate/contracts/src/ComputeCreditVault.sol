// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal exact-transfer ERC20 surface. Tokens are only accounting
///         assets; the vault never interprets decimals or consults a price oracle.
interface IComputeCreditERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice ERC-1271 contract-wallet signature surface. This lets Base smart
///         accounts authorize compute without weakening EOA ECDSA checks.
interface IComputeCreditERC1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);
}

/// @title ComputeCreditVault - non-transferable, asset-denominated compute credits
/// @notice Sponsors deposit native ETH or an allowlisted ERC20 on behalf of a
///         project user. Deposits create only internal service-credit claims in
///         that exact asset; there is no token supply, transfer, redemption rate,
///         or price oracle. A user signs a bounded job authorization, reserving
///         its maximum debit. An approved TEE may settle once, under a frozen
///         compose-approval requirement, only with an independent metering
///         signer and a distinct attestation-QVL signer authorizing separate
///         EIP-712 typehashes over the same exact debit and execution context.
contract ComputeCreditVault {
    uint256 public constant GOVERNANCE_TIMELOCK = 2 days;
    uint256 public constant MAX_JOB_LIFETIME = 30 days;
    uint256 public constant MAX_METERING_RECEIPT_LIFETIME = 10 minutes;
    uint256 public constant MAX_DEVELOPER_FEE_BPS = 2000;
    uint256 private constant BPS_DENOMINATOR = 10_000;
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes4 private constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant NAME_HASH = keccak256("DNAI Compute Credit Vault");
    bytes32 public constant VERSION_HASH = keccak256("2");
    bytes32 public constant JOB_AUTHORIZATION_TYPEHASH = keccak256(
        "ComputeJobAuthorization(bytes32 projectId,bytes32 jobId,address user,address asset,uint256 nonce,uint256 maxAssetDebit,uint256 expiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment)"
    );
    bytes32 public constant METERING_RECEIPT_TYPEHASH = keccak256(
        "ComputeMeteringReceipt(bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 usageCommitment,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash,uint256 receiptExpiry)"
    );
    bytes32 public constant METERING_QVL_RECEIPT_TYPEHASH = keccak256(
        "ComputeMeteringQvlReceipt(bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 usageCommitment,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash,uint256 receiptExpiry)"
    );
    bytes32 public constant START_COMMITMENT_TYPEHASH = keccak256(
        "ComputeJobStart(uint256 chainId,address verifyingContract,bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 meteringPolicySetHash,uint256 startedAt)"
    );
    bytes32 public constant USAGE_COMMITMENT_TYPEHASH = keccak256(
        "ComputeMeteredUsage(uint256 chainId,address verifyingContract,bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash)"
    );

    enum JobState {
        None,
        Authorized,
        Started,
        Settled,
        Cancelled,
        Expired
    }

    struct CreditBalance {
        uint256 available;
        uint256 reserved;
    }

    struct JobAuthorization {
        bytes32 projectId;
        bytes32 jobId;
        address user;
        address asset;
        uint256 nonce;
        uint256 maxAssetDebit;
        uint256 expiry;
        bytes32 ratePolicyCommitment;
        bytes32 workloadCommitment;
        bytes32 manifestCommitment;
        bytes32 dispatchIntentCommitment;
    }

    struct Job {
        bytes32 projectId;
        address user;
        address asset;
        uint256 authorizationNonce;
        uint256 maxAssetDebit;
        uint256 actualAssetDebit;
        uint64 authorizationExpiry;
        uint64 startedAt;
        uint64 usageEndedAt;
        uint64 receiptExpiry;
        bytes32 ratePolicyCommitment;
        bytes32 workloadCommitment;
        bytes32 manifestCommitment;
        bytes32 dispatchIntentCommitment;
        bytes32 composeHash;
        bytes32 startCommitment;
        bytes32 usageCommitment;
        bytes32 attestationEvidenceHash;
        uint256 billableComputeUnits;
        address teeIdentity;
        JobState state;
    }

    struct RatePolicy {
        address asset;
        address provider;
        uint16 developerFeeBps;
        bool active;
    }

    struct RatePolicyProposal {
        address asset;
        address provider;
        uint16 developerFeeBps;
        uint64 activatesAt;
    }

    address public owner;
    address public pendingOwner;
    address public immutable developer;
    address public meteringVerifier;
    address public meteringQvlVerifier;
    bytes32 public meteringPolicySetHash;
    address public pendingMeteringVerifier;
    address public pendingMeteringQvlVerifier;
    bytes32 public pendingMeteringPolicySetHash;
    uint64 public pendingMeteringBindingActivatesAt;
    bool public meteringBindingFrozen;
    bool public paused;

    uint16 public developerFeeBps;
    uint16 public pendingDeveloperFeeBps;
    uint64 public pendingDeveloperFeeActivatesAt;
    bool public developerFeeFrozen;
    bool public assetAdditionsFrozen;
    bool public ratePolicyAdditionsFrozen;
    bool public composePolicyFrozen;
    bool public teeIdentityAdditionsFrozen;
    uint256 public allowedAssetCount;
    uint256 public activeRatePolicyCount;
    uint256 public approvedComposeCount;
    uint256 public approvedTeeIdentityCount;
    uint256 public pendingAssetCount;
    uint256 public pendingRatePolicyCount;
    uint256 public pendingComposeCount;
    uint256 public pendingTeeIdentityCount;

    mapping(address asset => bool allowed) public allowedAssets;
    mapping(address asset => uint64 activatesAt) public pendingAssetActivations;
    mapping(bytes32 commitment => RatePolicy policy) public ratePolicies;
    mapping(bytes32 commitment => RatePolicyProposal proposal) public pendingRatePolicies;
    mapping(bytes32 commitment => bool configured) public ratePolicyEverConfigured;
    mapping(address provider => bool configured) public providerEverApproved;
    mapping(bytes32 composeHash => bool approved) public approvedComposeHashes;
    mapping(bytes32 composeHash => uint64 activatesAt) public pendingComposeActivations;
    mapping(address teeIdentity => bytes32 composeHash) public teeIdentityComposeHash;
    mapping(address teeIdentity => bytes32 composeHash) public pendingTeeIdentityComposeHash;
    mapping(address teeIdentity => uint64 activatesAt) public pendingTeeIdentityActivations;
    mapping(address teeIdentity => bool configured) public teeIdentityEverApproved;
    mapping(address verifier => bool configured) public meteringVerifierEverConfigured;
    mapping(address verifier => bool configured) public meteringQvlVerifierEverConfigured;

    mapping(bytes32 projectId => mapping(address user => mapping(address asset => CreditBalance balance))) public
        credits;
    mapping(bytes32 projectId => mapping(address user => uint256 nonce)) public nextAuthorizationNonce;
    mapping(bytes32 jobId => Job job) private _jobs;
    mapping(address asset => mapping(address recipient => uint256 amount)) public claimableAccrual;
    mapping(address asset => uint256 amount) public totalLiability;

    uint256 private _reentrancyLock = 1;

    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PauseSet(bool paused);
    event DeveloperFeeProposed(uint256 newFeeBps, uint256 activatesAt);
    event DeveloperFeeActivated(uint256 newFeeBps);
    event DeveloperFeeProposalCancelled(uint256 proposedFeeBps);
    event DeveloperFeeFrozen(uint256 finalFeeBps);
    event AssetProposed(address indexed asset, uint256 activatesAt);
    event AssetActivated(address indexed asset);
    event AssetProposalCancelled(address indexed asset);
    event AssetRevoked(address indexed asset);
    event AssetAdditionsFrozen();
    event RatePolicyProposed(
        bytes32 indexed commitment,
        address indexed asset,
        address indexed provider,
        uint256 developerFeeBps,
        uint256 activatesAt
    );
    event RatePolicyActivated(
        bytes32 indexed commitment, address indexed asset, address indexed provider, uint256 developerFeeBps
    );
    event RatePolicyProposalCancelled(bytes32 indexed commitment);
    event RatePolicyRevoked(bytes32 indexed commitment);
    event RatePolicyAdditionsFrozen();
    event ComposeHashProposed(bytes32 indexed composeHash, uint256 activatesAt);
    event ComposeHashApproved(bytes32 indexed composeHash);
    event ComposeHashProposalCancelled(bytes32 indexed composeHash);
    event ComposeHashRevoked(bytes32 indexed composeHash);
    event MeteringBindingProposed(
        address indexed verifier, address indexed qvlVerifier, bytes32 indexed policySetHash, uint256 activatesAt
    );
    event MeteringBindingActivated(
        address indexed verifier, address indexed qvlVerifier, bytes32 indexed policySetHash
    );
    event MeteringBindingProposalCancelled(
        address indexed verifier, address indexed qvlVerifier, bytes32 indexed policySetHash
    );
    event MeteringBindingFrozen(address indexed verifier, address indexed qvlVerifier, bytes32 indexed policySetHash);
    event TeeIdentityProposed(address indexed teeIdentity, bytes32 indexed composeHash, uint256 activatesAt);
    event TeeIdentityApproved(address indexed teeIdentity, bytes32 indexed composeHash);
    event TeeIdentityProposalCancelled(address indexed teeIdentity, bytes32 indexed composeHash);
    event TeeIdentityRevoked(address indexed teeIdentity);
    event TeeIdentityAdditionsFrozen();
    event ComposePolicyFrozen();
    event CreditFunded(
        bytes32 indexed projectId, address indexed beneficiary, address indexed asset, address sponsor, uint256 amount
    );
    event AuthorizationNonceInvalidated(
        bytes32 indexed projectId, address indexed user, uint256 previousNonce, uint256 newNonce
    );
    event JobAuthorized(
        bytes32 indexed jobId,
        bytes32 indexed projectId,
        address indexed user,
        address asset,
        uint256 nonce,
        uint256 maxAssetDebit,
        uint256 expiry,
        bytes32 ratePolicyCommitment,
        bytes32 workloadCommitment,
        bytes32 manifestCommitment,
        bytes32 dispatchIntentCommitment
    );
    event JobCancelled(bytes32 indexed jobId, address indexed user, uint256 releasedAmount);
    event JobExpired(bytes32 indexed jobId, address indexed user, uint256 releasedAmount);
    event JobStarted(
        bytes32 indexed jobId,
        address indexed teeIdentity,
        bytes32 indexed composeHash,
        bytes32 startCommitment,
        bytes32 workloadCommitment,
        bytes32 manifestCommitment,
        bytes32 dispatchIntentCommitment,
        uint256 startedAt
    );
    event JobMetered(
        bytes32 indexed jobId,
        address indexed teeIdentity,
        bytes32 indexed composeHash,
        address asset,
        uint256 actualAssetDebit,
        uint256 providerAccrual,
        uint256 developerAccrual,
        uint256 unusedReleased,
        bytes32 startCommitment,
        bytes32 usageCommitment,
        bytes32 workloadCommitment,
        bytes32 manifestCommitment,
        bytes32 dispatchIntentCommitment,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 meteringPolicySetHash,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry
    );
    event UnusedCreditWithdrawn(bytes32 indexed projectId, address indexed user, address indexed asset, uint256 amount);
    event AccrualWithdrawn(address indexed recipient, address indexed asset, uint256 amount);

    error NotOwner();
    error NotPendingOwner();
    error NotJobUser();
    error ZeroAddress();
    error ZeroAmount();
    error ZeroCommitment();
    error RoleConflict();
    error Paused();
    error NoStateChange();
    error TimelockNotElapsed(uint256 activatesAt);
    error ProposalExists();
    error ProposalMissing();
    error GovernanceFrozen();
    error PendingAdmissions();
    error FeeTooHigh();
    error AssetNotAllowed();
    error InvalidAsset();
    error AssetAmountMismatch();
    error RatePolicyNotActive();
    error RatePolicyAlreadyConfigured();
    error DeveloperFeeNotFrozen();
    error FeePolicyMismatch();
    error ComposeHashNotApproved();
    error ComposePolicyNotFrozen();
    error TeeIdentityNotApproved();
    error ComposeIdentityMismatch();
    error ReleasePolicyNotReady();
    error InvalidJobState(JobState expected, JobState actual);
    error JobNotOpen(JobState actual);
    error JobAlreadyExists();
    error InvalidAuthorizationNonce(uint256 expected, uint256 supplied);
    error InvalidAuthorizationExpiry();
    error InvalidReceiptExpiry();
    error InvalidMeteredUsage();
    error InvalidSignature();
    error InvalidMeteringSignature();
    error InvalidMeteringQvlSignature();
    error InsufficientAvailableCredit();
    error DebitExceedsJobCap();
    error NothingToWithdraw();
    error TransferFailed();
    error Insolvent();
    error Reentrancy();
    error DirectCustodyDisabled();
    error TimestampOverflow();

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    modifier whenNotPaused() {
        _checkNotPaused();
        _requireReleasePolicyReady();
        _;
    }

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    constructor(address initialOwner, address developerRecipient, uint16 initialFeeBps) {
        if (initialOwner == address(0) || developerRecipient == address(0)) revert ZeroAddress();
        if (initialOwner == developerRecipient || initialOwner == address(this) || developerRecipient == address(this)) revert RoleConflict();
        if (initialFeeBps > MAX_DEVELOPER_FEE_BPS) revert FeeTooHigh();

        owner = initialOwner;
        developer = developerRecipient;
        developerFeeBps = initialFeeBps;
        paused = true;

        emit OwnershipTransferred(address(0), initialOwner);
        emit DeveloperFeeActivated(initialFeeBps);
        emit PauseSet(true);
    }

    // ── Ownership and emergency controls ──────────────────────────────

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == owner) revert NoStateChange();
        if (_isServiceRole(newOwner)) revert RoleConflict();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        // Re-check at acceptance: the current owner may have changed service
        // roles after beginning the two-step transfer.
        if (_isServiceRole(msg.sender)) revert RoleConflict();
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    function setPaused(bool newPaused) external onlyOwner {
        if (paused == newPaused) revert NoStateChange();
        if (!newPaused) _requireReleasePolicyReady();
        paused = newPaused;
        emit PauseSet(newPaused);
    }

    // ── Timelocked/freezeable developer fee ──────────────────────────

    function proposeDeveloperFee(uint16 newFeeBps) external onlyOwner {
        if (developerFeeFrozen) revert GovernanceFrozen();
        if (newFeeBps > MAX_DEVELOPER_FEE_BPS) revert FeeTooHigh();
        if (pendingDeveloperFeeActivatesAt != 0) revert ProposalExists();
        pendingDeveloperFeeBps = newFeeBps;
        pendingDeveloperFeeActivatesAt = _timelockActivation();
        emit DeveloperFeeProposed(newFeeBps, pendingDeveloperFeeActivatesAt);
    }

    function activateDeveloperFee() external onlyOwner {
        if (developerFeeFrozen) revert GovernanceFrozen();
        uint64 activatesAt = pendingDeveloperFeeActivatesAt;
        if (activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < activatesAt) revert TimelockNotElapsed(activatesAt);
        developerFeeBps = pendingDeveloperFeeBps;
        pendingDeveloperFeeBps = 0;
        pendingDeveloperFeeActivatesAt = 0;
        emit DeveloperFeeActivated(developerFeeBps);
    }

    function cancelDeveloperFeeProposal() external onlyOwner {
        if (pendingDeveloperFeeActivatesAt == 0) revert ProposalMissing();
        uint16 proposed = pendingDeveloperFeeBps;
        pendingDeveloperFeeBps = 0;
        pendingDeveloperFeeActivatesAt = 0;
        emit DeveloperFeeProposalCancelled(proposed);
    }

    function freezeDeveloperFee() external onlyOwner {
        if (developerFeeFrozen) revert GovernanceFrozen();
        developerFeeFrozen = true;
        pendingDeveloperFeeBps = 0;
        pendingDeveloperFeeActivatesAt = 0;
        emit DeveloperFeeFrozen(developerFeeBps);
    }

    // ── Timelocked ERC20 allowlist; native ETH is always supported ───

    function proposeAsset(address asset) external onlyOwner {
        if (assetAdditionsFrozen) revert GovernanceFrozen();
        _requireErc20(asset);
        if (allowedAssets[asset] || pendingAssetActivations[asset] != 0) revert ProposalExists();
        uint64 activatesAt = _timelockActivation();
        pendingAssetActivations[asset] = activatesAt;
        pendingAssetCount += 1;
        emit AssetProposed(asset, activatesAt);
    }

    function activateAsset(address asset) external onlyOwner {
        if (assetAdditionsFrozen) revert GovernanceFrozen();
        uint64 activatesAt = pendingAssetActivations[asset];
        if (activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < activatesAt) revert TimelockNotElapsed(activatesAt);
        _requireErc20(asset);
        delete pendingAssetActivations[asset];
        pendingAssetCount -= 1;
        allowedAssets[asset] = true;
        allowedAssetCount += 1;
        emit AssetActivated(asset);
    }

    function cancelAssetProposal(address asset) external onlyOwner {
        if (pendingAssetActivations[asset] == 0) revert ProposalMissing();
        delete pendingAssetActivations[asset];
        pendingAssetCount -= 1;
        emit AssetProposalCancelled(asset);
    }

    function revokeAsset(address asset) external onlyOwner {
        if (!allowedAssets[asset]) revert AssetNotAllowed();
        allowedAssets[asset] = false;
        allowedAssetCount -= 1;
        emit AssetRevoked(asset);
    }

    function freezeAssetAdditions() external onlyOwner {
        if (assetAdditionsFrozen) revert GovernanceFrozen();
        if (pendingAssetCount != 0) revert PendingAdmissions();
        assetAdditionsFrozen = true;
        emit AssetAdditionsFrozen();
    }

    // ── Timelocked/freezeable rate policies ──────────────────────────

    function proposeRatePolicy(bytes32 commitment, address asset, address provider, uint16 expectedDeveloperFeeBps)
        external
        onlyOwner
    {
        if (ratePolicyAdditionsFrozen) revert GovernanceFrozen();
        if (!developerFeeFrozen) revert DeveloperFeeNotFrozen();
        if (commitment == bytes32(0)) revert ZeroCommitment();
        if (provider == address(0)) revert ZeroAddress();
        _validateProviderRole(provider);
        if (!_assetAllowed(asset)) revert AssetNotAllowed();
        if (expectedDeveloperFeeBps != developerFeeBps) revert FeePolicyMismatch();
        if (ratePolicyEverConfigured[commitment] || pendingRatePolicies[commitment].activatesAt != 0) {
            revert RatePolicyAlreadyConfigured();
        }

        uint64 activatesAt = _timelockActivation();
        pendingRatePolicies[commitment] = RatePolicyProposal({
            asset: asset, provider: provider, developerFeeBps: expectedDeveloperFeeBps, activatesAt: activatesAt
        });
        pendingRatePolicyCount += 1;
        emit RatePolicyProposed(commitment, asset, provider, expectedDeveloperFeeBps, activatesAt);
    }

    function activateRatePolicy(bytes32 commitment) external onlyOwner {
        if (ratePolicyAdditionsFrozen) revert GovernanceFrozen();
        RatePolicyProposal memory proposal = pendingRatePolicies[commitment];
        if (proposal.activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < proposal.activatesAt) revert TimelockNotElapsed(proposal.activatesAt);
        if (!_assetAllowed(proposal.asset)) revert AssetNotAllowed();
        _validateProviderRole(proposal.provider);
        if (proposal.developerFeeBps != developerFeeBps) revert FeePolicyMismatch();

        delete pendingRatePolicies[commitment];
        pendingRatePolicyCount -= 1;
        ratePolicyEverConfigured[commitment] = true;
        providerEverApproved[proposal.provider] = true;
        ratePolicies[commitment] = RatePolicy({
            asset: proposal.asset, provider: proposal.provider, developerFeeBps: proposal.developerFeeBps, active: true
        });
        activeRatePolicyCount += 1;
        emit RatePolicyActivated(commitment, proposal.asset, proposal.provider, proposal.developerFeeBps);
    }

    function cancelRatePolicyProposal(bytes32 commitment) external onlyOwner {
        if (pendingRatePolicies[commitment].activatesAt == 0) revert ProposalMissing();
        delete pendingRatePolicies[commitment];
        pendingRatePolicyCount -= 1;
        emit RatePolicyProposalCancelled(commitment);
    }

    function revokeRatePolicy(bytes32 commitment) external onlyOwner {
        RatePolicy storage policy = ratePolicies[commitment];
        if (!policy.active) revert RatePolicyNotActive();
        policy.active = false;
        activeRatePolicyCount -= 1;
        emit RatePolicyRevoked(commitment);
    }

    function freezeRatePolicyAdditions() external onlyOwner {
        if (ratePolicyAdditionsFrozen) revert GovernanceFrozen();
        if (pendingRatePolicyCount != 0) revert PendingAdmissions();
        ratePolicyAdditionsFrozen = true;
        emit RatePolicyAdditionsFrozen();
    }

    // ── Timelocked metering-root binding ──────────────────────────────

    /// @notice Stage the independent meter and metering-QVL signers with the
    ///         exact metering policy-set hash both are allowed to attest.
    ///         The vault deliberately deploys without these values so its
    ///         runtime bytecode can be included in that policy set without a
    ///         constructor-argument fixed point.
    function proposeMeteringBinding(address verifier, address qvlVerifier, bytes32 policySetHash) external onlyOwner {
        if (meteringBindingFrozen) revert GovernanceFrozen();
        if (verifier == address(0) || qvlVerifier == address(0)) revert ZeroAddress();
        if (verifier == qvlVerifier) revert RoleConflict();
        if (policySetHash == bytes32(0)) revert ZeroCommitment();
        if (pendingMeteringBindingActivatesAt != 0) revert ProposalExists();
        if (
            verifier == meteringVerifier && qvlVerifier == meteringQvlVerifier && policySetHash == meteringPolicySetHash
        ) revert NoStateChange();
        _validateMeteringVerifierRole(verifier);
        _validateMeteringQvlVerifierRole(qvlVerifier);

        pendingMeteringVerifier = verifier;
        pendingMeteringQvlVerifier = qvlVerifier;
        pendingMeteringPolicySetHash = policySetHash;
        pendingMeteringBindingActivatesAt = _timelockActivation();
        emit MeteringBindingProposed(verifier, qvlVerifier, policySetHash, pendingMeteringBindingActivatesAt);
    }

    function activateMeteringBinding() external onlyOwner {
        if (meteringBindingFrozen) revert GovernanceFrozen();
        uint64 activatesAt = pendingMeteringBindingActivatesAt;
        if (activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < activatesAt) revert TimelockNotElapsed(activatesAt);
        address verifier = pendingMeteringVerifier;
        address qvlVerifier = pendingMeteringQvlVerifier;
        bytes32 policySetHash = pendingMeteringPolicySetHash;
        if (verifier == address(0) || qvlVerifier == address(0)) revert ZeroAddress();
        if (verifier == qvlVerifier) revert RoleConflict();
        _validateMeteringVerifierRole(verifier);
        _validateMeteringQvlVerifierRole(qvlVerifier);

        meteringVerifier = verifier;
        meteringQvlVerifier = qvlVerifier;
        meteringPolicySetHash = policySetHash;
        meteringVerifierEverConfigured[verifier] = true;
        meteringQvlVerifierEverConfigured[qvlVerifier] = true;
        pendingMeteringVerifier = address(0);
        pendingMeteringQvlVerifier = address(0);
        pendingMeteringPolicySetHash = bytes32(0);
        pendingMeteringBindingActivatesAt = 0;
        emit MeteringBindingActivated(verifier, qvlVerifier, policySetHash);
    }

    function cancelMeteringBindingProposal() external onlyOwner {
        if (pendingMeteringBindingActivatesAt == 0) revert ProposalMissing();
        address verifier = pendingMeteringVerifier;
        address qvlVerifier = pendingMeteringQvlVerifier;
        bytes32 policySetHash = pendingMeteringPolicySetHash;
        pendingMeteringVerifier = address(0);
        pendingMeteringQvlVerifier = address(0);
        pendingMeteringPolicySetHash = bytes32(0);
        pendingMeteringBindingActivatesAt = 0;
        emit MeteringBindingProposalCancelled(verifier, qvlVerifier, policySetHash);
    }

    function freezeMeteringBinding() external onlyOwner {
        if (meteringBindingFrozen) revert GovernanceFrozen();
        if (pendingMeteringBindingActivatesAt != 0) revert PendingAdmissions();
        if (
            meteringVerifier == address(0) || meteringQvlVerifier == address(0)
                || meteringVerifier == meteringQvlVerifier || meteringPolicySetHash == bytes32(0)
        ) revert ReleasePolicyNotReady();
        meteringBindingFrozen = true;
        emit MeteringBindingFrozen(meteringVerifier, meteringQvlVerifier, meteringPolicySetHash);
    }

    // ── Timelocked compose and TEE identity admission ─────────────────

    function proposeComposeHash(bytes32 composeHash) external onlyOwner {
        if (composePolicyFrozen) revert GovernanceFrozen();
        if (composeHash == bytes32(0)) revert ZeroCommitment();
        if (approvedComposeHashes[composeHash] || pendingComposeActivations[composeHash] != 0) {
            revert ProposalExists();
        }
        uint64 activatesAt = _timelockActivation();
        pendingComposeActivations[composeHash] = activatesAt;
        pendingComposeCount += 1;
        emit ComposeHashProposed(composeHash, activatesAt);
    }

    function activateComposeHash(bytes32 composeHash) external onlyOwner {
        if (composePolicyFrozen) revert GovernanceFrozen();
        uint64 activatesAt = pendingComposeActivations[composeHash];
        if (activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < activatesAt) revert TimelockNotElapsed(activatesAt);
        delete pendingComposeActivations[composeHash];
        pendingComposeCount -= 1;
        approvedComposeHashes[composeHash] = true;
        approvedComposeCount += 1;
        emit ComposeHashApproved(composeHash);
    }

    function cancelComposeHashProposal(bytes32 composeHash) external onlyOwner {
        if (pendingComposeActivations[composeHash] == 0) revert ProposalMissing();
        delete pendingComposeActivations[composeHash];
        pendingComposeCount -= 1;
        emit ComposeHashProposalCancelled(composeHash);
    }

    function revokeComposeHash(bytes32 composeHash) external onlyOwner {
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        approvedComposeHashes[composeHash] = false;
        approvedComposeCount -= 1;
        emit ComposeHashRevoked(composeHash);
    }

    function proposeTeeIdentity(address teeIdentity, bytes32 composeHash) external onlyOwner {
        if (teeIdentityAdditionsFrozen) revert GovernanceFrozen();
        if (teeIdentity == address(0)) revert ZeroAddress();
        _validateTeeIdentityRole(teeIdentity);
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        if (teeIdentityComposeHash[teeIdentity] != bytes32(0) || pendingTeeIdentityActivations[teeIdentity] != 0) {
            revert ProposalExists();
        }
        uint64 activatesAt = _timelockActivation();
        pendingTeeIdentityComposeHash[teeIdentity] = composeHash;
        pendingTeeIdentityActivations[teeIdentity] = activatesAt;
        pendingTeeIdentityCount += 1;
        emit TeeIdentityProposed(teeIdentity, composeHash, activatesAt);
    }

    function activateTeeIdentity(address teeIdentity) external onlyOwner {
        if (teeIdentityAdditionsFrozen) revert GovernanceFrozen();
        uint64 activatesAt = pendingTeeIdentityActivations[teeIdentity];
        if (activatesAt == 0) revert ProposalMissing();
        if (block.timestamp < activatesAt) revert TimelockNotElapsed(activatesAt);
        bytes32 composeHash = pendingTeeIdentityComposeHash[teeIdentity];
        _validateTeeIdentityRole(teeIdentity);
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        delete pendingTeeIdentityComposeHash[teeIdentity];
        delete pendingTeeIdentityActivations[teeIdentity];
        pendingTeeIdentityCount -= 1;
        teeIdentityComposeHash[teeIdentity] = composeHash;
        teeIdentityEverApproved[teeIdentity] = true;
        approvedTeeIdentityCount += 1;
        emit TeeIdentityApproved(teeIdentity, composeHash);
    }

    function cancelTeeIdentityProposal(address teeIdentity) external onlyOwner {
        if (pendingTeeIdentityActivations[teeIdentity] == 0) revert ProposalMissing();
        bytes32 composeHash = pendingTeeIdentityComposeHash[teeIdentity];
        delete pendingTeeIdentityComposeHash[teeIdentity];
        delete pendingTeeIdentityActivations[teeIdentity];
        pendingTeeIdentityCount -= 1;
        emit TeeIdentityProposalCancelled(teeIdentity, composeHash);
    }

    function revokeTeeIdentity(address teeIdentity) external onlyOwner {
        if (teeIdentityComposeHash[teeIdentity] == bytes32(0)) revert TeeIdentityNotApproved();
        delete teeIdentityComposeHash[teeIdentity];
        approvedTeeIdentityCount -= 1;
        emit TeeIdentityRevoked(teeIdentity);
    }

    /// @notice Permanently close the reviewed compose-hash admission set.
    ///         Existing hashes remain immediately revocable for incident response.
    function freezeComposePolicy() external onlyOwner {
        if (composePolicyFrozen) revert GovernanceFrozen();
        if (approvedComposeCount == 0) revert ComposeHashNotApproved();
        if (pendingComposeCount != 0) revert PendingAdmissions();
        composePolicyFrozen = true;
        emit ComposePolicyFrozen();
    }

    /// @notice Permanently close the reviewed TEE identity admission set.
    ///         Existing identities remain immediately revocable for incident response.
    function freezeTeeIdentityAdditions() external onlyOwner {
        if (teeIdentityAdditionsFrozen) revert GovernanceFrozen();
        if (pendingTeeIdentityCount != 0) revert PendingAdmissions();
        if (approvedTeeIdentityCount == 0) revert TeeIdentityNotApproved();
        teeIdentityAdditionsFrozen = true;
        emit TeeIdentityAdditionsFrozen();
    }

    // ── Funding creates non-transferable service-credit claims ────────

    function fundNative(bytes32 projectId, address beneficiary) external payable whenNotPaused nonReentrant {
        _validateFunding(projectId, beneficiary, msg.value);
        _creditFunding(projectId, beneficiary, address(0), msg.value);
    }

    function fundERC20(bytes32 projectId, address beneficiary, address asset, uint256 amount)
        external
        whenNotPaused
        nonReentrant
    {
        _validateFunding(projectId, beneficiary, amount);
        if (!allowedAssets[asset]) revert AssetNotAllowed();
        _requireErc20(asset);

        uint256 beforeBalance = _assetBalance(asset, address(this));
        _safeTransferFrom(asset, msg.sender, address(this), amount);
        uint256 afterBalance = _assetBalance(asset, address(this));
        if (afterBalance < beforeBalance || afterBalance - beforeBalance != amount) {
            revert AssetAmountMismatch();
        }
        _creditFunding(projectId, beneficiary, asset, amount);
    }

    // ── User authorization, cancellation, and expiry ─────────────────

    function authorizeJob(JobAuthorization calldata authorization, bytes calldata userSignature)
        external
        whenNotPaused
    {
        if (
            authorization.projectId == bytes32(0) || authorization.jobId == bytes32(0)
                || authorization.ratePolicyCommitment == bytes32(0) || authorization.workloadCommitment == bytes32(0)
                || authorization.manifestCommitment == bytes32(0)
                || authorization.dispatchIntentCommitment == bytes32(0)
        ) revert ZeroCommitment();
        if (authorization.user == address(0)) revert ZeroAddress();
        if (authorization.maxAssetDebit == 0) revert ZeroAmount();
        if (
            authorization.expiry <= block.timestamp || authorization.expiry > block.timestamp + MAX_JOB_LIFETIME
                || authorization.expiry > type(uint64).max
        ) revert InvalidAuthorizationExpiry();
        if (_jobs[authorization.jobId].state != JobState.None) revert JobAlreadyExists();

        RatePolicy memory policy = ratePolicies[authorization.ratePolicyCommitment];
        if (!policy.active) revert RatePolicyNotActive();
        if (policy.asset != authorization.asset || !_assetAllowed(authorization.asset)) {
            revert AssetNotAllowed();
        }

        uint256 expectedNonce = nextAuthorizationNonce[authorization.projectId][authorization.user];
        if (authorization.nonce != expectedNonce) {
            revert InvalidAuthorizationNonce(expectedNonce, authorization.nonce);
        }
        if (!_isValidSigner(authorization.user, jobAuthorizationDigest(authorization), userSignature)) {
            revert InvalidSignature();
        }

        CreditBalance storage balance = credits[authorization.projectId][authorization.user][authorization.asset];
        if (authorization.maxAssetDebit > balance.available) revert InsufficientAvailableCredit();

        nextAuthorizationNonce[authorization.projectId][authorization.user] = expectedNonce + 1;
        balance.available -= authorization.maxAssetDebit;
        balance.reserved += authorization.maxAssetDebit;
        _jobs[authorization.jobId] = Job({
            projectId: authorization.projectId,
            user: authorization.user,
            asset: authorization.asset,
            authorizationNonce: authorization.nonce,
            maxAssetDebit: authorization.maxAssetDebit,
            actualAssetDebit: 0,
            authorizationExpiry: uint64(authorization.expiry),
            startedAt: 0,
            usageEndedAt: 0,
            receiptExpiry: 0,
            ratePolicyCommitment: authorization.ratePolicyCommitment,
            workloadCommitment: authorization.workloadCommitment,
            manifestCommitment: authorization.manifestCommitment,
            dispatchIntentCommitment: authorization.dispatchIntentCommitment,
            composeHash: bytes32(0),
            startCommitment: bytes32(0),
            usageCommitment: bytes32(0),
            attestationEvidenceHash: bytes32(0),
            billableComputeUnits: 0,
            teeIdentity: address(0),
            state: JobState.Authorized
        });

        emit JobAuthorized(
            authorization.jobId,
            authorization.projectId,
            authorization.user,
            authorization.asset,
            authorization.nonce,
            authorization.maxAssetDebit,
            authorization.expiry,
            authorization.ratePolicyCommitment,
            authorization.workloadCommitment,
            authorization.manifestCommitment,
            authorization.dispatchIntentCommitment
        );
    }

    function invalidateAuthorizationNonce(bytes32 projectId, uint256 newNonce) external {
        if (projectId == bytes32(0)) revert ZeroCommitment();
        uint256 current = nextAuthorizationNonce[projectId][msg.sender];
        if (newNonce <= current) revert InvalidAuthorizationNonce(current + 1, newNonce);
        nextAuthorizationNonce[projectId][msg.sender] = newNonce;
        emit AuthorizationNonceInvalidated(projectId, msg.sender, current, newNonce);
    }

    function cancelJob(bytes32 jobId) external {
        Job storage job = _getJob(jobId);
        if (msg.sender != job.user) revert NotJobUser();
        if (job.state != JobState.Authorized) revert InvalidJobState(JobState.Authorized, job.state);
        job.state = JobState.Cancelled;
        _releaseReservation(job);
        emit JobCancelled(jobId, job.user, job.maxAssetDebit);
    }

    function expireJob(bytes32 jobId) external {
        Job storage job = _getJob(jobId);
        if (job.state != JobState.Authorized && job.state != JobState.Started) revert JobNotOpen(job.state);
        if (block.timestamp <= job.authorizationExpiry) revert InvalidAuthorizationExpiry();
        job.state = JobState.Expired;
        _releaseReservation(job);
        emit JobExpired(jobId, job.user, job.maxAssetDebit);
    }

    // ── Independently authorized TEE metering settlement ─────────────

    /// @notice Irreversibly marks a bounded authorization as dispatched.
    ///         The start commitment is derived here from the complete signed
    ///         authorization, the frozen release policy, the admitted TEE and
    ///         this block timestamp. The TEE cannot inject an opaque value.
    function startJob(bytes32 jobId, bytes32 composeHash) external whenNotPaused {
        Job storage job = _getJob(jobId);
        if (job.state != JobState.Authorized) revert InvalidJobState(JobState.Authorized, job.state);
        if (block.timestamp > job.authorizationExpiry) revert InvalidAuthorizationExpiry();
        if (block.timestamp > type(uint64).max) revert TimestampOverflow();
        _validateExecutionGate(msg.sender, composeHash, job);

        uint64 startedAt = uint64(block.timestamp);
        bytes32 startCommitment = _deriveStartCommitment(jobId, job, msg.sender, composeHash, startedAt);
        job.composeHash = composeHash;
        job.startCommitment = startCommitment;
        job.startedAt = startedAt;
        job.teeIdentity = msg.sender;
        job.state = JobState.Started;
        emit JobStarted(
            jobId,
            msg.sender,
            composeHash,
            startCommitment,
            job.workloadCommitment,
            job.manifestCommitment,
            job.dispatchIntentCommitment,
            startedAt
        );
    }

    function submitMeteringReceipt(
        bytes32 jobId,
        uint256 actualAssetDebit,
        bytes32 composeHash,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry,
        bytes calldata verifierSignature,
        bytes calldata qvlSignature
    ) external whenNotPaused {
        Job storage job = _getJob(jobId);
        if (job.state != JobState.Started) revert InvalidJobState(JobState.Started, job.state);
        if (block.timestamp > job.authorizationExpiry) revert InvalidAuthorizationExpiry();
        if (
            receiptExpiry < block.timestamp || receiptExpiry > block.timestamp + MAX_METERING_RECEIPT_LIFETIME
                || receiptExpiry > job.authorizationExpiry || receiptExpiry > type(uint64).max
        ) {
            revert InvalidReceiptExpiry();
        }
        if (actualAssetDebit > job.maxAssetDebit) revert DebitExceedsJobCap();
        if (
            billableComputeUnits == 0 || usageStartedAt != job.startedAt || usageEndedAt < usageStartedAt
                || usageEndedAt > block.timestamp || usageEndedAt > type(uint64).max
        ) revert InvalidMeteredUsage();
        if (attestationEvidenceHash == bytes32(0)) revert ZeroCommitment();
        if (msg.sender != job.teeIdentity || composeHash != job.composeHash) revert ComposeIdentityMismatch();
        RatePolicy memory policy = _validateExecutionGate(msg.sender, composeHash, job);

        bytes32 usageCommitment = _deriveUsageCommitment(
            jobId, job, actualAssetDebit, billableComputeUnits, usageStartedAt, usageEndedAt, attestationEvidenceHash
        );
        bytes32 meterDigest = _meteringReceiptDigest(
            METERING_RECEIPT_TYPEHASH,
            jobId,
            job,
            actualAssetDebit,
            billableComputeUnits,
            usageStartedAt,
            usageEndedAt,
            usageCommitment,
            attestationEvidenceHash,
            receiptExpiry
        );
        if (!_isValidSigner(meteringVerifier, meterDigest, verifierSignature)) {
            revert InvalidMeteringSignature();
        }
        bytes32 qvlDigest = _meteringReceiptDigest(
            METERING_QVL_RECEIPT_TYPEHASH,
            jobId,
            job,
            actualAssetDebit,
            billableComputeUnits,
            usageStartedAt,
            usageEndedAt,
            usageCommitment,
            attestationEvidenceHash,
            receiptExpiry
        );
        if (!_isValidSigner(meteringQvlVerifier, qvlDigest, qvlSignature)) {
            revert InvalidMeteringQvlSignature();
        }

        CreditBalance storage balance = credits[job.projectId][job.user][job.asset];
        if (balance.reserved < job.maxAssetDebit) revert Insolvent();
        uint256 unused = job.maxAssetDebit - actualAssetDebit;
        balance.reserved -= job.maxAssetDebit;
        balance.available += unused;

        uint256 developerAmount = _mulBps(actualAssetDebit, policy.developerFeeBps);
        uint256 providerAmount = actualAssetDebit - developerAmount;
        claimableAccrual[job.asset][policy.provider] += providerAmount;
        claimableAccrual[job.asset][developer] += developerAmount;

        job.actualAssetDebit = actualAssetDebit;
        job.billableComputeUnits = billableComputeUnits;
        // The validation above proves both values fit exactly in the storage width.
        // forge-lint: disable-next-line(unsafe-typecast)
        job.usageEndedAt = uint64(usageEndedAt);
        // forge-lint: disable-next-line(unsafe-typecast)
        job.receiptExpiry = uint64(receiptExpiry);
        job.usageCommitment = usageCommitment;
        job.attestationEvidenceHash = attestationEvidenceHash;
        job.state = JobState.Settled;

        emit JobMetered(
            jobId,
            msg.sender,
            composeHash,
            job.asset,
            actualAssetDebit,
            providerAmount,
            developerAmount,
            unused,
            job.startCommitment,
            usageCommitment,
            job.workloadCommitment,
            job.manifestCommitment,
            job.dispatchIntentCommitment,
            billableComputeUnits,
            usageStartedAt,
            usageEndedAt,
            meteringPolicySetHash,
            attestationEvidenceHash,
            receiptExpiry
        );
    }

    // ── Pull-based withdrawals; internal credits are never transferable ─

    function withdrawUnused(bytes32 projectId, address asset, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        CreditBalance storage balance = credits[projectId][msg.sender][asset];
        if (amount > balance.available) revert InsufficientAvailableCredit();
        balance.available -= amount;
        totalLiability[asset] -= amount;
        _transferAssetExact(asset, msg.sender, amount);
        emit UnusedCreditWithdrawn(projectId, msg.sender, asset, amount);
    }

    function withdrawAccrued(address asset) external nonReentrant {
        uint256 amount = claimableAccrual[asset][msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        claimableAccrual[asset][msg.sender] = 0;
        totalLiability[asset] -= amount;
        _transferAssetExact(asset, msg.sender, amount);
        emit AccrualWithdrawn(msg.sender, asset, amount);
    }

    // ── Typed-data and accounting views ───────────────────────────────

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function jobAuthorizationDigest(JobAuthorization calldata authorization) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                JOB_AUTHORIZATION_TYPEHASH,
                authorization.projectId,
                authorization.jobId,
                authorization.user,
                authorization.asset,
                authorization.nonce,
                authorization.maxAssetDebit,
                authorization.expiry,
                authorization.ratePolicyCommitment,
                authorization.workloadCommitment,
                authorization.manifestCommitment,
                authorization.dispatchIntentCommitment
            )
        );
        return _hashTypedData(structHash);
    }

    function meteringReceiptDigest(
        bytes32 jobId,
        uint256 actualAssetDebit,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry
    ) public view returns (bytes32) {
        Job storage job = _getJob(jobId);
        bytes32 usageCommitment = _deriveUsageCommitment(
            jobId, job, actualAssetDebit, billableComputeUnits, usageStartedAt, usageEndedAt, attestationEvidenceHash
        );
        return _meteringReceiptDigest(
            METERING_RECEIPT_TYPEHASH,
            jobId,
            job,
            actualAssetDebit,
            billableComputeUnits,
            usageStartedAt,
            usageEndedAt,
            usageCommitment,
            attestationEvidenceHash,
            receiptExpiry
        );
    }

    function meteringQvlReceiptDigest(
        bytes32 jobId,
        uint256 actualAssetDebit,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry
    ) public view returns (bytes32) {
        Job storage job = _getJob(jobId);
        bytes32 usageCommitment = _deriveUsageCommitment(
            jobId, job, actualAssetDebit, billableComputeUnits, usageStartedAt, usageEndedAt, attestationEvidenceHash
        );
        return _meteringReceiptDigest(
            METERING_QVL_RECEIPT_TYPEHASH,
            jobId,
            job,
            actualAssetDebit,
            billableComputeUnits,
            usageStartedAt,
            usageEndedAt,
            usageCommitment,
            attestationEvidenceHash,
            receiptExpiry
        );
    }

    function usageCommitmentFor(
        bytes32 jobId,
        uint256 actualAssetDebit,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 attestationEvidenceHash
    ) external view returns (bytes32) {
        Job storage job = _getJob(jobId);
        return _deriveUsageCommitment(
            jobId, job, actualAssetDebit, billableComputeUnits, usageStartedAt, usageEndedAt, attestationEvidenceHash
        );
    }

    function startCommitmentFor(bytes32 jobId, address teeIdentity, bytes32 composeHash, uint256 startedAt)
        external
        view
        returns (bytes32)
    {
        if (startedAt > type(uint64).max) revert TimestampOverflow();
        Job storage job = _getJob(jobId);
        // The explicit upper-bound check above makes this narrowing exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        return _deriveStartCommitment(jobId, job, teeIdentity, composeHash, uint64(startedAt));
    }

    function getJob(bytes32 jobId) external view returns (Job memory) {
        return _getJob(jobId);
    }

    function vaultAssetBalance(address asset) public view returns (uint256) {
        return _assetBalance(asset, address(this));
    }

    function surplus(address asset) external view returns (uint256) {
        uint256 balance = vaultAssetBalance(asset);
        uint256 liability = totalLiability[asset];
        if (balance < liability) revert Insolvent();
        return balance - liability;
    }

    // ── Internal helpers ──────────────────────────────────────────────

    function _deriveStartCommitment(
        bytes32 jobId,
        Job storage job,
        address teeIdentity,
        bytes32 composeHash,
        uint64 startedAt
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                START_COMMITMENT_TYPEHASH,
                block.chainid,
                address(this),
                job.projectId,
                jobId,
                job.user,
                job.asset,
                job.authorizationNonce,
                job.maxAssetDebit,
                uint256(job.authorizationExpiry),
                job.ratePolicyCommitment,
                job.workloadCommitment,
                job.manifestCommitment,
                job.dispatchIntentCommitment,
                teeIdentity,
                composeHash,
                meteringPolicySetHash,
                uint256(startedAt)
            )
        );
    }

    function _deriveUsageCommitment(
        bytes32 jobId,
        Job storage job,
        uint256 actualAssetDebit,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 attestationEvidenceHash
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                USAGE_COMMITMENT_TYPEHASH,
                block.chainid,
                address(this),
                job.projectId,
                jobId,
                job.user,
                job.asset,
                job.authorizationNonce,
                job.maxAssetDebit,
                actualAssetDebit,
                uint256(job.authorizationExpiry),
                job.ratePolicyCommitment,
                job.workloadCommitment,
                job.manifestCommitment,
                job.dispatchIntentCommitment,
                job.teeIdentity,
                job.composeHash,
                job.startCommitment,
                billableComputeUnits,
                usageStartedAt,
                usageEndedAt,
                meteringPolicySetHash,
                attestationEvidenceHash
            )
        );
    }

    function _meteringReceiptDigest(
        bytes32 receiptTypehash,
        bytes32 jobId,
        Job storage job,
        uint256 actualAssetDebit,
        uint256 billableComputeUnits,
        uint256 usageStartedAt,
        uint256 usageEndedAt,
        bytes32 usageCommitment,
        bytes32 attestationEvidenceHash,
        uint256 receiptExpiry
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                receiptTypehash,
                job.projectId,
                jobId,
                job.user,
                job.asset,
                job.authorizationNonce,
                job.maxAssetDebit,
                actualAssetDebit,
                uint256(job.authorizationExpiry),
                job.ratePolicyCommitment,
                job.workloadCommitment,
                job.manifestCommitment,
                job.dispatchIntentCommitment,
                job.teeIdentity,
                job.composeHash,
                job.startCommitment,
                billableComputeUnits,
                usageStartedAt,
                usageEndedAt,
                usageCommitment,
                meteringPolicySetHash,
                attestationEvidenceHash,
                receiptExpiry
            )
        );
        return _hashTypedData(structHash);
    }

    function _creditFunding(bytes32 projectId, address beneficiary, address asset, uint256 amount) internal {
        credits[projectId][beneficiary][asset].available += amount;
        totalLiability[asset] += amount;
        emit CreditFunded(projectId, beneficiary, asset, msg.sender, amount);
    }

    function _validateFunding(bytes32 projectId, address beneficiary, uint256 amount) internal pure {
        if (projectId == bytes32(0)) revert ZeroCommitment();
        if (beneficiary == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
    }

    function _releaseReservation(Job storage job) internal {
        CreditBalance storage balance = credits[job.projectId][job.user][job.asset];
        if (balance.reserved < job.maxAssetDebit) revert Insolvent();
        balance.reserved -= job.maxAssetDebit;
        balance.available += job.maxAssetDebit;
    }

    function _getJob(bytes32 jobId) internal view returns (Job storage job) {
        job = _jobs[jobId];
        if (job.state == JobState.None) revert InvalidJobState(JobState.Authorized, JobState.None);
    }

    function _assetAllowed(address asset) internal view returns (bool) {
        return asset == address(0) || allowedAssets[asset];
    }

    function _requireErc20(address asset) internal view {
        if (asset == address(0) || asset.code.length == 0) revert InvalidAsset();
    }

    function _assetBalance(address asset, address account) internal view returns (uint256 balance) {
        if (asset == address(0)) return account.balance;
        _requireErc20(asset);
        (bool ok, bytes memory data) =
            asset.staticcall(abi.encodeWithSelector(IComputeCreditERC20.balanceOf.selector, account));
        if (!ok || data.length < 32) revert TransferFailed();
        balance = abi.decode(data, (uint256));
    }

    function _safeTransferFrom(address asset, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            asset.call(abi.encodeWithSelector(IComputeCreditERC20.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && (data.length < 32 || !abi.decode(data, (bool))))) {
            revert TransferFailed();
        }
    }

    function _transferAssetExact(address asset, address recipient, uint256 amount) internal {
        if (asset == address(0)) {
            (bool nativeOk,) = payable(recipient).call{value: amount}("");
            if (!nativeOk) revert TransferFailed();
            return;
        }

        uint256 vaultBefore = _assetBalance(asset, address(this));
        uint256 recipientBefore = _assetBalance(asset, recipient);
        (bool ok, bytes memory data) =
            asset.call(abi.encodeWithSelector(IComputeCreditERC20.transfer.selector, recipient, amount));
        if (!ok || (data.length != 0 && (data.length < 32 || !abi.decode(data, (bool))))) {
            revert TransferFailed();
        }
        uint256 vaultAfter = _assetBalance(asset, address(this));
        uint256 recipientAfter = _assetBalance(asset, recipient);
        if (
            vaultAfter > vaultBefore || vaultBefore - vaultAfter != amount || recipientAfter < recipientBefore
                || recipientAfter - recipientBefore != amount
        ) revert AssetAmountMismatch();
    }

    function _mulBps(uint256 value, uint256 bps) internal pure returns (uint256) {
        uint256 quotient = value / BPS_DENOMINATOR;
        uint256 remainder = value % BPS_DENOMINATOR;
        return (quotient * bps) + ((remainder * bps) / BPS_DENOMINATOR);
    }

    function _timelockActivation() internal view returns (uint64) {
        uint256 activation = block.timestamp + GOVERNANCE_TIMELOCK;
        if (activation > type(uint64).max) revert TimestampOverflow();
        // The explicit upper-bound check above makes this narrowing exact.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(activation);
    }

    function _checkOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _checkNotPaused() internal view {
        if (paused) revert Paused();
    }

    function _isServiceRole(address account) internal view returns (bool) {
        return account == address(this) || account == developer || account == meteringVerifier
            || account == meteringQvlVerifier || account == pendingMeteringVerifier
            || account == pendingMeteringQvlVerifier || meteringVerifierEverConfigured[account]
            || meteringQvlVerifierEverConfigured[account] || providerEverApproved[account]
            || teeIdentityEverApproved[account] || teeIdentityComposeHash[account] != bytes32(0)
            || pendingTeeIdentityActivations[account] != 0;
    }

    function _validateMeteringVerifierRole(address verifier) internal view {
        if (
            verifier == address(this) || verifier == owner || verifier == pendingOwner || verifier == developer
                || providerEverApproved[verifier] || teeIdentityEverApproved[verifier]
                || teeIdentityComposeHash[verifier] != bytes32(0) || pendingTeeIdentityActivations[verifier] != 0
                || verifier == meteringQvlVerifier || verifier == pendingMeteringQvlVerifier
                || meteringQvlVerifierEverConfigured[verifier]
        ) revert RoleConflict();
    }

    function _validateMeteringQvlVerifierRole(address verifier) internal view {
        if (
            verifier == address(this) || verifier == owner || verifier == pendingOwner || verifier == developer
                || providerEverApproved[verifier] || teeIdentityEverApproved[verifier]
                || teeIdentityComposeHash[verifier] != bytes32(0) || pendingTeeIdentityActivations[verifier] != 0
                || verifier == meteringVerifier || verifier == pendingMeteringVerifier
                || meteringVerifierEverConfigured[verifier]
        ) revert RoleConflict();
    }

    function _validateTeeIdentityRole(address teeIdentity) internal view {
        if (
            teeIdentity == address(this) || teeIdentity == owner || teeIdentity == pendingOwner
                || teeIdentity == developer || teeIdentity == meteringVerifier || teeIdentity == pendingMeteringVerifier
                || teeIdentity == meteringQvlVerifier || teeIdentity == pendingMeteringQvlVerifier
                || meteringVerifierEverConfigured[teeIdentity] || meteringQvlVerifierEverConfigured[teeIdentity]
                || providerEverApproved[teeIdentity]
        ) revert RoleConflict();
    }

    function _validateProviderRole(address provider) internal view {
        if (
            provider == address(this) || provider == owner || provider == pendingOwner || provider == developer
                || provider == meteringVerifier || provider == pendingMeteringVerifier
                || provider == meteringQvlVerifier || provider == pendingMeteringQvlVerifier
                || meteringVerifierEverConfigured[provider] || meteringQvlVerifierEverConfigured[provider]
                || teeIdentityEverApproved[provider] || teeIdentityComposeHash[provider] != bytes32(0)
                || pendingTeeIdentityActivations[provider] != 0
        ) revert RoleConflict();
    }

    function _requireReleasePolicyReady() internal view {
        if (
            !developerFeeFrozen || !assetAdditionsFrozen || !ratePolicyAdditionsFrozen || !composePolicyFrozen
                || !teeIdentityAdditionsFrozen || !meteringBindingFrozen || meteringVerifier == address(0)
                || meteringQvlVerifier == address(0) || meteringVerifier == meteringQvlVerifier
                || meteringPolicySetHash == bytes32(0) || allowedAssetCount != 1 || activeRatePolicyCount != 2
                || approvedComposeCount != 1 || approvedTeeIdentityCount != 1 || pendingDeveloperFeeActivatesAt != 0
                || pendingAssetCount != 0 || pendingRatePolicyCount != 0 || pendingComposeCount != 0
                || pendingTeeIdentityCount != 0 || pendingMeteringBindingActivatesAt != 0
        ) revert ReleasePolicyNotReady();
    }

    function _validateExecutionGate(address teeIdentity, bytes32 composeHash, Job storage job)
        internal
        view
        returns (RatePolicy memory policy)
    {
        _requireReleasePolicyReady();
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        bytes32 registeredCompose = teeIdentityComposeHash[teeIdentity];
        if (registeredCompose == bytes32(0)) revert TeeIdentityNotApproved();
        if (registeredCompose != composeHash) revert ComposeIdentityMismatch();
        policy = ratePolicies[job.ratePolicyCommitment];
        if (!policy.active) revert RatePolicyNotActive();
        if (policy.asset != job.asset || !_assetAllowed(job.asset)) revert AssetNotAllowed();
    }

    function _nonReentrantBefore() internal {
        if (_reentrancyLock != 1) revert Reentrancy();
        _reentrancyLock = 2;
    }

    function _nonReentrantAfter() internal {
        _reentrancyLock = 1;
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _isValidSigner(address signer, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        if (signer.code.length == 0) return _recover(digest, signature) == signer;
        (bool ok, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(IComputeCreditERC1271.isValidSignature.selector, digest, signature)
        );
        return ok && result.length >= 32 && abi.decode(result, (bytes4)) == ERC1271_MAGIC_VALUE;
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v != 27 && v != 28) revert InvalidSignature();
        if (uint256(r) == 0 || uint256(s) == 0 || uint256(s) > SECP256K1_HALF_ORDER) {
            revert InvalidSignature();
        }
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }

    receive() external payable {
        revert DirectCustodyDisabled();
    }

    fallback() external payable {
        revert DirectCustodyDisabled();
    }
}
