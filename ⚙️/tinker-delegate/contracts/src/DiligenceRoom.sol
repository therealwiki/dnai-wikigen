// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC20 surface used for stablecoin (e.g. USDC) settlement.
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title DiligenceRoom — NDAI escrow for attested ML evaluations
/// @notice Minimal escrow state machine on Base Sepolia. Seller lists artifact,
///         buyer funds evaluation, a verifier authorizes an attested TEE result,
///         and the TEE submits bounded output for three-way settlement. A deal
///         settles either in native ETH (`paymentToken == address(0)`) or in an
///         ERC20 stablecoin; the settlement math is identical for both.
contract DiligenceRoom {
    // ── State machine ──────────────────────────────────────────────────
    enum State {
        Created, // Seller listed, awaiting buyer
        Funded, // Buyer funded, awaiting TEE evaluation
        Evaluated, // TEE submitted result, awaiting buyer decision
        Accepted, // Buyer accepted — seller paid
        Rejected, // Buyer rejected — seller gets nothing
        Expired // Deadline passed — refund
    }

    // ── Score bands (bounded output — never raw scores) ────────────────
    enum ScoreBand {
        Negligible, // <1% improvement
        Low, // 1-5%
        Medium, // 5-10%
        High, // 10-20%
        Exceptional // >20%
    }

    // ── Deal storage ───────────────────────────────────────────────────
    struct Deal {
        address seller;
        address buyer;
        uint256 reservePrice; // min payment seller will accept (wei)
        uint256 budgetCap; // max buyer will pay (wei)
        uint256 expiry; // unix timestamp
        State state;
        // V2 commitment to exact raw bytes:
        // keccak256("dnai-wikigen/artifact-commitment/v2" || 0x00 || secret32 || rawArtifact).
        // The 32-byte secret stays inside the TEE-encrypted wrapper and never
        // appears on-chain. The contract stores this commitment opaquely; the
        // attested evaluator enforces the preimage relation before evaluation.
        bytes32 artifactHash;
        address teeIdentity; // TEE-derived address (from KMS key)
        // Evaluation result (set by TEE)
        ScoreBand scoreBand;
        uint256 computeCost; // public policy tariff; exact Tinker metering stays private
        uint256 fee; // 1% surcharge
        bytes32 resultHash; // canonical hash of bounded public result fields
        bytes32 resultComposeHash; // verified compose/app measurement binding
        // Appended last so the positional `deals()` decode of the leading
        // fields (used by the off-chain submitter) is unchanged.
        address paymentToken; // address(0) = native ETH, else ERC20 token
        // Exact, versioned deterministic evaluator recipe selected by the
        // buyer. This is committed atomically with funding and never changes.
        // The production evaluator resolves this opaque commitment only to a
        // reviewed bounded, no-network recipe; it is not arbitrary code input.
        bytes32 evaluatorPolicyCommitment;
        // Hash-only independent attestation evidence. Raw TDX quotes and QVL
        // collateral never enter contract storage or events.
        bytes32 attestationEvidenceHash;
        uint256 resultAuthorizationExpiry;
        uint256 attestationAuthorizationExpiry;
    }

    // ── Constants ──────────────────────────────────────────────────────
    uint256 public constant DEFAULT_FEE_BPS = 100; // 1% = 100 basis points
    uint256 public constant MAX_FEE_BPS = 1000; // hard cap: 10%
    uint256 public constant COMPUTE_SETTLEMENT_BPS = 100; // fixed 1% public tariff
    uint256 public constant FEE_TIMELOCK_DELAY = 2 days;
    uint256 public constant ADMISSION_TIMELOCK_DELAY = 2 days;
    uint256 public constant ATTESTATION_BINDING_TIMELOCK_DELAY = 2 days;
    uint256 public constant MAX_RESULT_AUTHORIZATION_LIFETIME = 10 minutes;
    // EIP-2 lower-half-order bound. Rejecting high-s signatures makes each
    // authorization canonical and avoids accepting malleated verifier proofs.
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 public constant RESULT_AUTHORIZATION_TYPEHASH = keccak256(
        "DiligenceRoomResultAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,bytes32 resultHash,bytes32 attestationReleasePolicyHash,uint256 authorizationExpiry)"
    );
    bytes32 public constant ATTESTATION_AUTHORIZATION_TYPEHASH = keccak256(
        "DiligenceRoomQVLAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,bytes32 resultHash,bytes32 attestationReleasePolicyHash,bytes32 attestationEvidenceHash,uint256 authorizationExpiry)"
    );
    bytes32 public constant PUBLIC_RESULT_TYPEHASH = keccak256(
        "DiligenceRoomPublicResult(uint256 chainId,address contractAddress,uint256 dealId,address seller,address buyer,uint256 reservePrice,uint256 budgetCap,uint256 expiry,bytes32 artifactHash,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,uint8 scoreBand,uint256 computeCost)"
    );
    /// @dev Compatibility-only recipe for explicit non-production rooms. It
    ///      cannot be selected in a production deployment.
    bytes32 public constant LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT =
        keccak256("dnai-wikigen/evaluator-policy/legacy-local-only/v1");
    bytes32 public constant EVALUATOR_POLICY_SET_TYPEHASH =
        keccak256("DiligenceRoomEvaluatorPolicySet(bytes32[3] evaluatorPolicies)");
    uint256 public constant REQUIRED_EVALUATOR_POLICY_COUNT = 3;

    // ── State ──────────────────────────────────────────────────────────
    address public immutable developer;
    /// @notice Constructor-bound release posture. Production rooms are
    /// fail-closed from the deployment transaction itself and cannot admit,
    /// fund, or evaluate a deal until every reviewed attestation and
    /// governance binding is complete. Local/legacy test rooms may opt out.
    bool public immutable productionRelease;
    /// @notice Result signer admitted after deployment under the same fixed
    /// review delay as the other release roots. Fresh deployments leave this
    /// unset so a CVM-derived identity is never smuggled into a constructor.
    address public resultVerifier;
    address public pendingResultVerifier;
    uint256 public pendingResultVerifierActivatesAt;
    bool public resultVerifierFrozen;
    mapping(uint256 => Deal) public deals;
    // token (address(0)=ETH) => recipient => claimable amount
    mapping(address => mapping(address => uint256)) public pendingWithdrawals;
    uint256 public nextDealId;

    // Protocol fee (basis points of the public compute tariff), governed by a
    // timelock and permanently freezable. The fee applied to a deal is locked at
    // submitResult time (stored on the Deal), so a later change never retroacts
    // on already-evaluated deals. Default 1%; capped at MAX_FEE_BPS.
    uint256 public feeBps = DEFAULT_FEE_BPS;
    uint256 public pendingFeeBps;
    uint256 public pendingFeeBpsActivatesAt;
    bool public feeBpsFrozen;
    // One-way production gate. Legacy/local deployments may leave it disabled,
    // while every fresh suite enables it before admitting a TEE identity.
    bool public computeSettlementPolicyEnabled;

    // On-chain governance of attested TEE measurements. When
    // `composeApprovalRequired` is enabled, submitResult also requires the
    // authorized composeHash to be developer-approved on-chain, so a result
    // cannot settle from a measurement that governance has not admitted — even
    // if the off-chain resultVerifier signs it. Default false preserves the
    // verifier-signature-only path; production deployments enable it to bind
    // teeIdentity to a governance-approved compose/app measurement.
    mapping(bytes32 => bool) public approvedComposeHashes;
    mapping(bytes32 => uint256) public pendingComposeActivations;
    uint256 public approvedComposeCount;
    uint256 public pendingComposeCount;
    bool public composeAdditionsFrozen;
    bool public composeApprovalRequired;

    // On-chain binding of a TEE identity to its attested measurement. When
    // `teeIdentityApprovalRequired` is enabled, `createDeal` requires the
    // seller-supplied `teeIdentity` to be developer-approved, and `submitResult`
    // requires the submitted compose hash to equal the identity's registered
    // compose hash — so a deal can only be created for, and settled by, a TEE
    // whose identity governance has bound to a specific measurement. A nonzero
    // value means approved; it records the compose hash the identity is bound to.
    // Default false preserves the bare-address behavior.
    mapping(address => bytes32) public teeIdentityComposeHash;
    mapping(address => bytes32) public pendingTeeIdentityComposeHash;
    mapping(address => uint256) public pendingTeeIdentityActivations;
    uint256 public approvedTeeIdentityCount;
    uint256 public pendingTeeIdentityCount;
    bool public teeIdentityAdditionsFrozen;
    bool public teeIdentityApprovalRequired;
    // One-way release invariant. Once frozen, neither approval requirement can
    // be disabled. Separate one-way admission freezes close the exact release
    // set after the timelocks; emergency revocation always remains available.
    bool public approvalRequirementsFrozen;

    // Independent-QVL trust root for production settlement. The verifier
    // address cannot be known in the constructor: its dstack key is derived
    // from the final QVL release policy, and that policy binds this room's
    // deployed address. The pair is therefore admitted after deployment under
    // a fixed review delay, then permanently frozen before production use.
    address public attestationVerifier;
    bytes32 public attestationReleasePolicyHash;
    address public pendingAttestationVerifier;
    bytes32 public pendingAttestationReleasePolicyHash;
    uint256 public pendingAttestationBindingActivatesAt;
    bool public attestationBindingFrozen;

    // Exact production evaluator recipes. Each commitment resolves off-chain
    // to one versioned deterministic, bounded, no-network evaluator manifest.
    // The three-entry release set is timelocked, then permanently frozen.
    mapping(bytes32 => bool) public approvedEvaluatorPolicies;
    mapping(bytes32 => uint256) public pendingEvaluatorPolicyActivations;
    bytes32[3] private _evaluatorPolicies;
    uint256 public approvedEvaluatorPolicyCount;
    uint256 public pendingEvaluatorPolicyCount;
    bool public evaluatorPolicySetFrozen;
    bytes32 public evaluatorPolicySetRoot;

    uint256 private _reentrancyLock = 1;

    // ── Events ─────────────────────────────────────────────────────────
    event DealCreated(
        uint256 indexed dealId,
        address indexed seller,
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity,
        address paymentToken
    );
    event DealFunded(
        uint256 indexed dealId,
        address indexed buyer,
        uint256 budgetCap,
        address paymentToken,
        bytes32 evaluatorPolicyCommitment
    );
    event EvaluationSubmitted(uint256 indexed dealId, ScoreBand scoreBand, uint256 computeCost, bytes32 resultHash);
    event ResultAuthorized(
        uint256 indexed dealId,
        address indexed verifier,
        address indexed teeIdentity,
        bytes32 composeHash,
        bytes32 evaluatorPolicyCommitment,
        bytes32 attestationReleasePolicyHash,
        uint256 authorizationExpiry
    );
    event AttestationAuthorized(
        uint256 indexed dealId,
        address indexed verifier,
        bytes32 indexed attestationEvidenceHash,
        bytes32 attestationReleasePolicyHash,
        uint256 authorizationExpiry
    );
    event DealAccepted(uint256 indexed dealId, uint256 sellerPayment, uint256 devPayment, uint256 buyerRefund);
    event DealRejected(uint256 indexed dealId, uint256 devPayment, uint256 buyerRefund);
    event DealExpired(uint256 indexed dealId, uint256 refund);
    event PayoutAccrued(uint256 indexed dealId, address indexed recipient, address token, uint256 amount);
    event Withdrawal(address indexed recipient, address token, uint256 amount);
    event ComposeHashProposed(bytes32 indexed composeHash, uint256 activatesAt);
    event ComposeHashApproved(bytes32 indexed composeHash);
    event ComposeHashProposalCancelled(bytes32 indexed composeHash);
    event ComposeHashRevoked(bytes32 indexed composeHash);
    event ComposeApprovalRequirementSet(bool required);
    event ComposeAdditionsFrozen();
    event TeeIdentityProposed(address indexed teeIdentity, bytes32 indexed composeHash, uint256 activatesAt);
    event TeeIdentityApproved(address indexed teeIdentity, bytes32 composeHash);
    event TeeIdentityProposalCancelled(address indexed teeIdentity, bytes32 indexed composeHash);
    event TeeIdentityRevoked(address indexed teeIdentity);
    event TeeIdentityApprovalRequirementSet(bool required);
    event TeeIdentityAdditionsFrozen();
    event ApprovalRequirementsFrozen();
    event ResultVerifierProposed(address indexed verifier, uint256 activatesAt);
    event ResultVerifierActivated(address indexed verifier);
    event ResultVerifierProposalCancelled(address indexed verifier);
    event ResultVerifierFrozen(address indexed verifier);
    event AttestationBindingProposed(address indexed verifier, bytes32 indexed releasePolicyHash, uint256 activatesAt);
    event AttestationBindingActivated(address indexed verifier, bytes32 indexed releasePolicyHash);
    event AttestationBindingProposalCancelled(address indexed verifier, bytes32 indexed releasePolicyHash);
    event AttestationBindingFrozen(address indexed verifier, bytes32 indexed releasePolicyHash);
    event FeeBpsProposed(uint256 newFeeBps, uint256 activatesAt);
    event FeeBpsActivated(uint256 newFeeBps);
    event FeeBpsProposalCancelled(uint256 proposedFeeBps);
    event FeeBpsFrozen(uint256 finalFeeBps);
    event ComputeSettlementPolicyEnabled(uint256 computeSettlementBps);
    event EvaluatorPolicyProposed(bytes32 indexed evaluatorPolicyCommitment, uint256 activatesAt);
    event EvaluatorPolicyApproved(bytes32 indexed evaluatorPolicyCommitment);
    event EvaluatorPolicyProposalCancelled(bytes32 indexed evaluatorPolicyCommitment);
    event EvaluatorPolicyRemoved(bytes32 indexed evaluatorPolicyCommitment);
    event EvaluatorPolicySetFrozen(bytes32 indexed evaluatorPolicySetRoot);

    // ── Errors ─────────────────────────────────────────────────────────
    error InvalidState(State expected, State actual);
    error DealNotFound();
    error InvalidExpiry();
    error ZeroArtifactHash();
    error ZeroTEEIdentity();
    error NotSeller();
    error NotBuyer();
    error NotTEE();
    error InsufficientFunding();
    error NotExpired();
    error AlreadyExpired();
    error ComputeCostOverBudget();
    error NothingToWithdraw();
    error TokenMismatch();
    error ZeroAmount();
    error PaymentBelowReserve();
    error PaymentAboveBudget();
    error TransferFailed();
    error ZeroResultVerifier();
    error ResultVerifierBindingFrozenError();
    error ResultVerifierProposalExists();
    error ResultVerifierProposalMissing();
    error ResultVerifierActivationTooEarly(uint256 activatesAt);
    error ResultVerifierNotReady();
    error ZeroComposeHash();
    error AuthorizationExpired();
    error AttestationAuthorizationExpired();
    error AuthorizationLifetimeTooLong();
    error InvalidResultAuthorization();
    error InvalidAttestationAuthorization();
    error NotDeveloper();
    error ComposeHashNotApproved();
    error TeeIdentityNotApproved();
    error ComposeHashIdentityMismatch();
    error ApprovalRequirementsFrozenError();
    error ApprovalRequirementsNotEnabled();
    error AdmissionAdditionsFrozen();
    error AdmissionProposalExists();
    error AdmissionProposalMissing();
    error AdmissionActivationTooEarly(uint256 activatesAt);
    error PendingAdmissions();
    error EmptyAdmissionSet();
    error RoleConflict();
    error ZeroAttestationVerifier();
    error ZeroAttestationReleasePolicyHash();
    error ZeroEvaluatorPolicyCommitment();
    error ZeroAttestationEvidenceHash();
    error LegacyFundingUnavailable();
    error EvaluatorPolicyNotApproved();
    error EvaluatorPolicySetFrozenError();
    error EvaluatorPolicySetFull();
    error EvaluatorPolicySetNotExact();
    error AttestationBindingFrozenError();
    error AttestationBindingProposalExists();
    error AttestationBindingProposalMissing();
    error AttestationBindingActivationTooEarly(uint256 activatesAt);
    error AttestationBindingNotReady();
    error FeeBpsFrozenError();
    error FeeBpsTooHigh();
    error NoFeeBpsPending();
    error FeeBpsProposalExists();
    error FeeActivationTooEarly(uint256 activatesAt);
    error ComputeSettlementPolicyAlreadyEnabled();
    error ComputeSettlementPolicyMismatch(uint256 expected, uint256 supplied);
    error InvalidPaymentToken();
    error TokenAmountMismatch();
    error Reentrancy();

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() internal {
        if (_reentrancyLock != 1) revert Reentrancy();
        _reentrancyLock = 2;
    }

    function _nonReentrantAfter() internal {
        _reentrancyLock = 1;
    }

    // ── Constructor ────────────────────────────────────────────────────
    constructor(bool initialProductionRelease) {
        developer = msg.sender;
        productionRelease = initialProductionRelease;
    }

    /// @notice Stage the result signer derived from the final main runtime.
    function proposeResultVerifier(address verifier) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (resultVerifierFrozen) revert ResultVerifierBindingFrozenError();
        if (verifier == address(0)) revert ZeroResultVerifier();
        if (
            verifier == developer || verifier == address(this) || verifier == attestationVerifier
                || verifier == pendingAttestationVerifier || teeIdentityComposeHash[verifier] != bytes32(0)
                || pendingTeeIdentityActivations[verifier] != 0
        ) revert RoleConflict();
        if (pendingResultVerifierActivatesAt != 0) revert ResultVerifierProposalExists();
        pendingResultVerifier = verifier;
        pendingResultVerifierActivatesAt = block.timestamp + ATTESTATION_BINDING_TIMELOCK_DELAY;
        emit ResultVerifierProposed(verifier, pendingResultVerifierActivatesAt);
    }

    function activateResultVerifier() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (resultVerifierFrozen) revert ResultVerifierBindingFrozenError();
        uint256 activatesAt = pendingResultVerifierActivatesAt;
        if (activatesAt == 0) revert ResultVerifierProposalMissing();
        if (block.timestamp < activatesAt) revert ResultVerifierActivationTooEarly(activatesAt);
        resultVerifier = pendingResultVerifier;
        pendingResultVerifier = address(0);
        pendingResultVerifierActivatesAt = 0;
        emit ResultVerifierActivated(resultVerifier);
    }

    function cancelResultVerifierProposal() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (pendingResultVerifierActivatesAt == 0) revert ResultVerifierProposalMissing();
        address verifier = pendingResultVerifier;
        pendingResultVerifier = address(0);
        pendingResultVerifierActivatesAt = 0;
        emit ResultVerifierProposalCancelled(verifier);
    }

    function freezeResultVerifier() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (resultVerifierFrozen) revert ResultVerifierBindingFrozenError();
        if (pendingResultVerifierActivatesAt != 0) revert ResultVerifierProposalExists();
        if (resultVerifier == address(0)) revert ResultVerifierNotReady();
        resultVerifierFrozen = true;
        emit ResultVerifierFrozen(resultVerifier);
    }

    // ── Independent attestation-verifier governance ──────────────────────────
    /// @notice Stage the exact independent QVL signer and its complete release
    ///         policy hash. The pair may be rotated only before it is frozen.
    function proposeAttestationBinding(address verifier, bytes32 releasePolicyHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (attestationBindingFrozen) revert AttestationBindingFrozenError();
        if (verifier == address(0)) revert ZeroAttestationVerifier();
        if (releasePolicyHash == bytes32(0)) revert ZeroAttestationReleasePolicyHash();
        if (
            verifier == developer || verifier == resultVerifier || verifier == pendingResultVerifier
                || verifier == address(this) || teeIdentityComposeHash[verifier] != bytes32(0)
                || pendingTeeIdentityActivations[verifier] != 0
        ) revert RoleConflict();
        if (pendingAttestationBindingActivatesAt != 0) revert AttestationBindingProposalExists();

        pendingAttestationVerifier = verifier;
        pendingAttestationReleasePolicyHash = releasePolicyHash;
        pendingAttestationBindingActivatesAt = block.timestamp + ATTESTATION_BINDING_TIMELOCK_DELAY;
        emit AttestationBindingProposed(verifier, releasePolicyHash, pendingAttestationBindingActivatesAt);
    }

    /// @notice Activate the staged independent-QVL binding after review.
    function activateAttestationBinding() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (attestationBindingFrozen) revert AttestationBindingFrozenError();
        uint256 activatesAt = pendingAttestationBindingActivatesAt;
        if (activatesAt == 0) revert AttestationBindingProposalMissing();
        if (block.timestamp < activatesAt) revert AttestationBindingActivationTooEarly(activatesAt);

        address verifier = pendingAttestationVerifier;
        bytes32 releasePolicyHash = pendingAttestationReleasePolicyHash;
        attestationVerifier = verifier;
        attestationReleasePolicyHash = releasePolicyHash;
        pendingAttestationVerifier = address(0);
        pendingAttestationReleasePolicyHash = bytes32(0);
        pendingAttestationBindingActivatesAt = 0;
        emit AttestationBindingActivated(verifier, releasePolicyHash);
    }

    /// @notice Cancel a staged QVL binding without changing the active pair.
    function cancelAttestationBindingProposal() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (pendingAttestationBindingActivatesAt == 0) revert AttestationBindingProposalMissing();
        address verifier = pendingAttestationVerifier;
        bytes32 releasePolicyHash = pendingAttestationReleasePolicyHash;
        pendingAttestationVerifier = address(0);
        pendingAttestationReleasePolicyHash = bytes32(0);
        pendingAttestationBindingActivatesAt = 0;
        emit AttestationBindingProposalCancelled(verifier, releasePolicyHash);
    }

    /// @notice Permanently lock the active independent-QVL trust root and
    ///         release policy. Rotation thereafter requires a new room.
    function freezeAttestationBinding() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (attestationBindingFrozen) revert AttestationBindingFrozenError();
        if (pendingAttestationBindingActivatesAt != 0) revert AttestationBindingProposalExists();
        if (attestationVerifier == address(0) || attestationReleasePolicyHash == bytes32(0)) {
            revert AttestationBindingNotReady();
        }
        attestationBindingFrozen = true;
        emit AttestationBindingFrozen(attestationVerifier, attestationReleasePolicyHash);
    }

    // ── Deterministic evaluator-recipe governance ─────────────────────
    function proposeEvaluatorPolicy(bytes32 evaluatorPolicyCommitment) external {
        if (msg.sender != developer) revert NotDeveloper();
        _proposeEvaluatorPolicy(evaluatorPolicyCommitment);
    }

    /// @notice Atomically stage the exact three-recipe release set. This is the
    ///         production ceremony path; individual proposal functions remain
    ///         available for explicit pre-freeze cancellation/removal recovery.
    function proposeEvaluatorPolicySet(bytes32[3] calldata evaluatorPolicies) external {
        if (msg.sender != developer) revert NotDeveloper();
        for (uint256 i = 0; i < REQUIRED_EVALUATOR_POLICY_COUNT; i++) {
            _proposeEvaluatorPolicy(evaluatorPolicies[i]);
        }
    }

    function _proposeEvaluatorPolicy(bytes32 evaluatorPolicyCommitment) internal {
        if (evaluatorPolicySetFrozen) revert EvaluatorPolicySetFrozenError();
        if (evaluatorPolicyCommitment == bytes32(0)) revert ZeroEvaluatorPolicyCommitment();
        if (
            approvedEvaluatorPolicies[evaluatorPolicyCommitment]
                || pendingEvaluatorPolicyActivations[evaluatorPolicyCommitment] != 0
        ) revert AdmissionProposalExists();
        if (approvedEvaluatorPolicyCount + pendingEvaluatorPolicyCount >= REQUIRED_EVALUATOR_POLICY_COUNT) {
            revert EvaluatorPolicySetFull();
        }
        uint256 activatesAt = block.timestamp + ADMISSION_TIMELOCK_DELAY;
        pendingEvaluatorPolicyActivations[evaluatorPolicyCommitment] = activatesAt;
        pendingEvaluatorPolicyCount += 1;
        emit EvaluatorPolicyProposed(evaluatorPolicyCommitment, activatesAt);
    }

    function activateEvaluatorPolicy(bytes32 evaluatorPolicyCommitment) external {
        if (msg.sender != developer) revert NotDeveloper();
        _activateEvaluatorPolicy(evaluatorPolicyCommitment);
    }

    function activateEvaluatorPolicySet(bytes32[3] calldata evaluatorPolicies) external {
        if (msg.sender != developer) revert NotDeveloper();
        for (uint256 i = 0; i < REQUIRED_EVALUATOR_POLICY_COUNT; i++) {
            _activateEvaluatorPolicy(evaluatorPolicies[i]);
        }
    }

    function _activateEvaluatorPolicy(bytes32 evaluatorPolicyCommitment) internal {
        if (evaluatorPolicySetFrozen) revert EvaluatorPolicySetFrozenError();
        uint256 activatesAt = pendingEvaluatorPolicyActivations[evaluatorPolicyCommitment];
        if (activatesAt == 0) revert AdmissionProposalMissing();
        if (block.timestamp < activatesAt) revert AdmissionActivationTooEarly(activatesAt);
        if (approvedEvaluatorPolicyCount >= REQUIRED_EVALUATOR_POLICY_COUNT) revert EvaluatorPolicySetFull();
        delete pendingEvaluatorPolicyActivations[evaluatorPolicyCommitment];
        pendingEvaluatorPolicyCount -= 1;
        approvedEvaluatorPolicies[evaluatorPolicyCommitment] = true;
        _evaluatorPolicies[approvedEvaluatorPolicyCount] = evaluatorPolicyCommitment;
        approvedEvaluatorPolicyCount += 1;
        emit EvaluatorPolicyApproved(evaluatorPolicyCommitment);
    }

    function cancelEvaluatorPolicyProposal(bytes32 evaluatorPolicyCommitment) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (pendingEvaluatorPolicyActivations[evaluatorPolicyCommitment] == 0) {
            revert AdmissionProposalMissing();
        }
        delete pendingEvaluatorPolicyActivations[evaluatorPolicyCommitment];
        pendingEvaluatorPolicyCount -= 1;
        emit EvaluatorPolicyProposalCancelled(evaluatorPolicyCommitment);
    }

    function removeEvaluatorPolicy(bytes32 evaluatorPolicyCommitment) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (evaluatorPolicySetFrozen) revert EvaluatorPolicySetFrozenError();
        if (!approvedEvaluatorPolicies[evaluatorPolicyCommitment]) revert EvaluatorPolicyNotApproved();
        uint256 count = approvedEvaluatorPolicyCount;
        uint256 found = count;
        for (uint256 i = 0; i < count; i++) {
            if (_evaluatorPolicies[i] == evaluatorPolicyCommitment) {
                found = i;
                break;
            }
        }
        if (found == count) revert EvaluatorPolicyNotApproved();
        for (uint256 i = found; i + 1 < count; i++) {
            _evaluatorPolicies[i] = _evaluatorPolicies[i + 1];
        }
        _evaluatorPolicies[count - 1] = bytes32(0);
        approvedEvaluatorPolicyCount = count - 1;
        delete approvedEvaluatorPolicies[evaluatorPolicyCommitment];
        emit EvaluatorPolicyRemoved(evaluatorPolicyCommitment);
    }

    function freezeEvaluatorPolicySet() external {
        if (msg.sender != developer) revert NotDeveloper();
        _freezeEvaluatorPolicySet();
    }

    function _freezeEvaluatorPolicySet() internal {
        if (evaluatorPolicySetFrozen) revert EvaluatorPolicySetFrozenError();
        if (approvedEvaluatorPolicyCount != REQUIRED_EVALUATOR_POLICY_COUNT || pendingEvaluatorPolicyCount != 0) {
            revert EvaluatorPolicySetNotExact();
        }
        bytes32[3] memory sorted = _sortedEvaluatorPolicies(_evaluatorPolicies);
        bytes32 root = keccak256(abi.encode(EVALUATOR_POLICY_SET_TYPEHASH, sorted));
        if (root == bytes32(0)) revert EvaluatorPolicySetNotExact();
        evaluatorPolicySetRoot = root;
        evaluatorPolicySetFrozen = true;
        emit EvaluatorPolicySetFrozen(root);
    }

    function evaluatorPolicies() external view returns (bytes32[3] memory) {
        return _evaluatorPolicies;
    }

    function computeEvaluatorPolicySetRoot(bytes32[3] memory evaluatorPolicies_) public pure returns (bytes32) {
        bytes32[3] memory sorted = _sortedEvaluatorPolicies(evaluatorPolicies_);
        return keccak256(abi.encode(EVALUATOR_POLICY_SET_TYPEHASH, sorted));
    }

    function _sortedEvaluatorPolicies(bytes32[3] memory values) internal pure returns (bytes32[3] memory) {
        for (uint256 i = 0; i < 2; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (values[j] < values[i]) {
                    (values[i], values[j]) = (values[j], values[i]);
                }
            }
        }
        return values;
    }

    // ── Developer governs approved TEE measurements ────────────────────
    /// @notice Stage a compose hash for admission after the fixed timelock.
    function proposeComposeHash(bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        _proposeComposeHash(composeHash);
    }

    /// @notice Ceremony-preserving batch transition: one EVM call stages the
    ///         release compose and the exact three evaluator recipes atomically.
    function proposeComposeAndEvaluatorPolicySet(bytes32 composeHash, bytes32[3] calldata evaluatorPolicies) external {
        if (msg.sender != developer) revert NotDeveloper();
        _proposeComposeHash(composeHash);
        for (uint256 i = 0; i < REQUIRED_EVALUATOR_POLICY_COUNT; i++) {
            _proposeEvaluatorPolicy(evaluatorPolicies[i]);
        }
    }

    function _proposeComposeHash(bytes32 composeHash) internal {
        if (composeAdditionsFrozen) revert AdmissionAdditionsFrozen();
        if (composeHash == bytes32(0)) revert ZeroComposeHash();
        if (approvedComposeHashes[composeHash] || pendingComposeActivations[composeHash] != 0) {
            revert AdmissionProposalExists();
        }
        uint256 activatesAt = block.timestamp + ADMISSION_TIMELOCK_DELAY;
        pendingComposeActivations[composeHash] = activatesAt;
        pendingComposeCount += 1;
        emit ComposeHashProposed(composeHash, activatesAt);
    }

    /// @notice Activate a staged compose hash after its review window elapses.
    function activateComposeHash(bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        _activateComposeHash(composeHash);
    }

    function activateComposeAndEvaluatorPolicySet(bytes32 composeHash, bytes32[3] calldata evaluatorPolicies) external {
        if (msg.sender != developer) revert NotDeveloper();
        _activateComposeHash(composeHash);
        for (uint256 i = 0; i < REQUIRED_EVALUATOR_POLICY_COUNT; i++) {
            _activateEvaluatorPolicy(evaluatorPolicies[i]);
        }
    }

    function _activateComposeHash(bytes32 composeHash) internal {
        if (composeAdditionsFrozen) revert AdmissionAdditionsFrozen();
        uint256 activatesAt = pendingComposeActivations[composeHash];
        if (activatesAt == 0) revert AdmissionProposalMissing();
        if (block.timestamp < activatesAt) revert AdmissionActivationTooEarly(activatesAt);
        delete pendingComposeActivations[composeHash];
        pendingComposeCount -= 1;
        approvedComposeHashes[composeHash] = true;
        approvedComposeCount += 1;
        emit ComposeHashApproved(composeHash);
    }

    /// @notice Cancel a staged compose hash without admitting it.
    function cancelComposeHashProposal(bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (pendingComposeActivations[composeHash] == 0) revert AdmissionProposalMissing();
        delete pendingComposeActivations[composeHash];
        pendingComposeCount -= 1;
        emit ComposeHashProposalCancelled(composeHash);
    }

    /// @notice Revoke a previously approved compose hash (e.g. after a rebuild).
    function revokeComposeHash(bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        approvedComposeHashes[composeHash] = false;
        approvedComposeCount -= 1;
        emit ComposeHashRevoked(composeHash);
    }

    /// @notice Permanently close compose admission while retaining revocation.
    function freezeComposeAdditions() external {
        if (msg.sender != developer) revert NotDeveloper();
        _freezeComposeAdditions();
    }

    function freezeComposeAndEvaluatorPolicySets() external {
        if (msg.sender != developer) revert NotDeveloper();
        _freezeComposeAdditions();
        _freezeEvaluatorPolicySet();
    }

    function _freezeComposeAdditions() internal {
        if (composeAdditionsFrozen) revert AdmissionAdditionsFrozen();
        if (pendingComposeCount != 0) revert PendingAdmissions();
        if (approvedComposeCount == 0) revert EmptyAdmissionSet();
        composeAdditionsFrozen = true;
        emit ComposeAdditionsFrozen();
    }

    /// @notice Enable/disable the compose gate until requirements are frozen.
    function setComposeApprovalRequired(bool required) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (approvalRequirementsFrozen) revert ApprovalRequirementsFrozenError();
        composeApprovalRequired = required;
        emit ComposeApprovalRequirementSet(required);
    }

    /// @notice Stage an exact TEE identity-to-compose binding for admission.
    function proposeTeeIdentity(address teeIdentity, bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (teeIdentityAdditionsFrozen) revert AdmissionAdditionsFrozen();
        if (teeIdentity == address(0)) revert ZeroTEEIdentity();
        if (
            teeIdentity == developer || teeIdentity == resultVerifier || teeIdentity == pendingResultVerifier
                || teeIdentity == address(this) || teeIdentity == attestationVerifier
                || teeIdentity == pendingAttestationVerifier
        ) {
            revert RoleConflict();
        }
        if (composeHash == bytes32(0)) revert ZeroComposeHash();
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        if (teeIdentityComposeHash[teeIdentity] != bytes32(0) || pendingTeeIdentityActivations[teeIdentity] != 0) {
            revert AdmissionProposalExists();
        }
        uint256 activatesAt = block.timestamp + ADMISSION_TIMELOCK_DELAY;
        pendingTeeIdentityComposeHash[teeIdentity] = composeHash;
        pendingTeeIdentityActivations[teeIdentity] = activatesAt;
        pendingTeeIdentityCount += 1;
        emit TeeIdentityProposed(teeIdentity, composeHash, activatesAt);
    }

    /// @notice Activate the exact staged TEE identity-to-compose binding.
    function activateTeeIdentity(address teeIdentity) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (teeIdentityAdditionsFrozen) revert AdmissionAdditionsFrozen();
        uint256 activatesAt = pendingTeeIdentityActivations[teeIdentity];
        if (activatesAt == 0) revert AdmissionProposalMissing();
        if (block.timestamp < activatesAt) revert AdmissionActivationTooEarly(activatesAt);
        bytes32 composeHash = pendingTeeIdentityComposeHash[teeIdentity];
        if (!approvedComposeHashes[composeHash]) revert ComposeHashNotApproved();
        delete pendingTeeIdentityComposeHash[teeIdentity];
        delete pendingTeeIdentityActivations[teeIdentity];
        pendingTeeIdentityCount -= 1;
        teeIdentityComposeHash[teeIdentity] = composeHash;
        approvedTeeIdentityCount += 1;
        emit TeeIdentityApproved(teeIdentity, composeHash);
    }

    /// @notice Cancel a staged TEE binding without admitting it.
    function cancelTeeIdentityProposal(address teeIdentity) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (pendingTeeIdentityActivations[teeIdentity] == 0) revert AdmissionProposalMissing();
        bytes32 composeHash = pendingTeeIdentityComposeHash[teeIdentity];
        delete pendingTeeIdentityComposeHash[teeIdentity];
        delete pendingTeeIdentityActivations[teeIdentity];
        pendingTeeIdentityCount -= 1;
        emit TeeIdentityProposalCancelled(teeIdentity, composeHash);
    }

    /// @notice Revoke a TEE identity binding (e.g. rotated key or retired image).
    function revokeTeeIdentity(address teeIdentity) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (teeIdentityComposeHash[teeIdentity] == bytes32(0)) revert TeeIdentityNotApproved();
        delete teeIdentityComposeHash[teeIdentity];
        approvedTeeIdentityCount -= 1;
        emit TeeIdentityRevoked(teeIdentity);
    }

    /// @notice Permanently close TEE-identity admission while retaining revocation.
    function freezeTeeIdentityAdditions() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (teeIdentityAdditionsFrozen) revert AdmissionAdditionsFrozen();
        if (pendingTeeIdentityCount != 0) revert PendingAdmissions();
        if (approvedTeeIdentityCount == 0) revert EmptyAdmissionSet();
        teeIdentityAdditionsFrozen = true;
        emit TeeIdentityAdditionsFrozen();
    }

    /// @notice Enable/disable the identity gate until requirements are frozen.
    function setTeeIdentityApprovalRequired(bool required) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (approvalRequirementsFrozen) revert ApprovalRequirementsFrozenError();
        teeIdentityApprovalRequired = required;
        emit TeeIdentityApprovalRequirementSet(required);
    }

    /// @notice Permanently lock both TEE approval gates in their enabled state.
    /// @dev Fresh releases call this before any TEE identity is admitted, leaving
    ///      the room fail-closed until a verified CVM binding clears both staged
    ///      admission windows. Addition freezes are applied after that binding.
    function freezeApprovalRequirements() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (approvalRequirementsFrozen) revert ApprovalRequirementsFrozenError();
        if (!composeApprovalRequired || !teeIdentityApprovalRequired) {
            revert ApprovalRequirementsNotEnabled();
        }
        approvalRequirementsFrozen = true;
        emit ApprovalRequirementsFrozen();
    }

    // ── Protocol-fee governance (timelock + freeze) ────────────────────
    /// @notice Propose a new protocol fee (bps). Activates after the timelock.
    function proposeFeeBps(uint256 newFeeBps) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (feeBpsFrozen) revert FeeBpsFrozenError();
        if (newFeeBps > MAX_FEE_BPS) revert FeeBpsTooHigh();
        if (pendingFeeBpsActivatesAt != 0) revert FeeBpsProposalExists();
        pendingFeeBps = newFeeBps;
        pendingFeeBpsActivatesAt = block.timestamp + FEE_TIMELOCK_DELAY;
        emit FeeBpsProposed(newFeeBps, pendingFeeBpsActivatesAt);
    }

    /// @notice Apply a proposed fee once its timelock has elapsed.
    function activateFeeBps() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (feeBpsFrozen) revert FeeBpsFrozenError();
        uint256 activatesAt = pendingFeeBpsActivatesAt;
        if (activatesAt == 0) revert NoFeeBpsPending();
        if (block.timestamp < activatesAt) revert FeeActivationTooEarly(activatesAt);
        feeBps = pendingFeeBps;
        pendingFeeBps = 0;
        pendingFeeBpsActivatesAt = 0;
        emit FeeBpsActivated(feeBps);
    }

    /// @notice Cancel a pending fee proposal.
    function cancelFeeBpsProposal() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (pendingFeeBpsActivatesAt == 0) revert NoFeeBpsPending();
        uint256 proposed = pendingFeeBps;
        pendingFeeBps = 0;
        pendingFeeBpsActivatesAt = 0;
        emit FeeBpsProposalCancelled(proposed);
    }

    /// @notice Permanently freeze the protocol fee at its current value.
    function freezeFeeBps() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (feeBpsFrozen) revert FeeBpsFrozenError();
        feeBpsFrozen = true;
        pendingFeeBps = 0;
        pendingFeeBpsActivatesAt = 0;
        emit FeeBpsFrozen(feeBps);
    }

    /// @notice Permanently require the fixed public compute tariff on results.
    /// @dev Exact token/call metering is intentionally not an on-chain field: an
    ///      evaluator that sees the artifact could otherwise modulate it as a
    ///      high-cardinality covert channel. Fresh deployments enable this once.
    function enableComputeSettlementPolicy() external {
        if (msg.sender != developer) revert NotDeveloper();
        if (computeSettlementPolicyEnabled) revert ComputeSettlementPolicyAlreadyEnabled();
        computeSettlementPolicyEnabled = true;
        emit ComputeSettlementPolicyEnabled(COMPUTE_SETTLEMENT_BPS);
    }

    /// @notice Deterministic tariff for an existing deal, derived only from its
    ///         already-public reserve, budget, and the governed fee rate.
    function policyComputeCost(uint256 dealId) external view returns (uint256) {
        Deal storage d = _getExistingDeal(dealId);
        return _policyComputeCost(d.reservePrice, d.budgetCap);
    }

    // ── Seller creates deal ────────────────────────────────────────────
    /// @notice Seller lists an artifact for evaluation
    /// @param reservePrice Minimum payment the seller will accept (wei)
    /// @param expiry Unix timestamp after which deal can be expired
    /// @param artifactHash Domain-separated salted v2 commitment to the exact raw
    ///        artifact bytes: keccak256("dnai-wikigen/artifact-commitment/v2" ||
    ///        0x00 || secret32 || rawArtifact). The secret is not published.
    /// @param teeIdentity Address derived from TEE's KMS key
    function createDeal(uint256 reservePrice, uint256 expiry, bytes32 artifactHash, address teeIdentity)
        external
        returns (uint256 dealId)
    {
        return _createDeal(reservePrice, expiry, artifactHash, teeIdentity, address(0));
    }

    /// @notice Seller lists an artifact for evaluation settled in an ERC20 token.
    /// @param artifactHash Same domain-separated salted v2 commitment defined by
    ///        the native-settlement overload; the bytes32 ABI is unchanged.
    /// @param paymentToken Nonzero ERC20 token address. Use the four-argument
    ///        overload for native ETH settlement.
    function createDeal(
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity,
        address paymentToken
    ) external returns (uint256 dealId) {
        _requirePaymentToken(paymentToken);
        return _createDeal(reservePrice, expiry, artifactHash, teeIdentity, paymentToken);
    }

    function _createDeal(
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity,
        address paymentToken
    ) internal returns (uint256 dealId) {
        _requireProductionAttestationBinding();
        if (expiry <= block.timestamp) revert InvalidExpiry();
        if (artifactHash == bytes32(0)) revert ZeroArtifactHash();
        if (teeIdentity == address(0)) revert ZeroTEEIdentity();
        if (teeIdentityApprovalRequired) {
            bytes32 admittedComposeHash = teeIdentityComposeHash[teeIdentity];
            if (admittedComposeHash == bytes32(0)) revert TeeIdentityNotApproved();
            // Revoking a compose hash is an emergency kill switch for both new
            // deal creation and result submission, even before the corresponding
            // TEE identity binding is separately revoked.
            if (!approvedComposeHashes[admittedComposeHash]) revert ComposeHashNotApproved();
        }

        dealId = nextDealId++;
        Deal storage d = _getExistingDeal(dealId);
        d.seller = msg.sender;
        d.reservePrice = reservePrice;
        d.expiry = expiry;
        d.artifactHash = artifactHash;
        d.teeIdentity = teeIdentity;
        d.paymentToken = paymentToken;
        d.state = State.Created;

        emit DealCreated(dealId, msg.sender, reservePrice, expiry, artifactHash, teeIdentity, paymentToken);
    }

    // ── Buyer funds deal ───────────────────────────────────────────────
    /// @notice Compatibility-only local funding path. Production callers must
    ///         select an exact evaluator recipe in the same funding transaction.
    function fundDeal(uint256 dealId) external payable {
        if (productionRelease) revert LegacyFundingUnavailable();
        _fundDeal(dealId, LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT);
    }

    /// @notice Buyer atomically funds the deal and commits the one exact,
    ///         versioned deterministic evaluator recipe authorized for it.
    /// @dev The commitment is bound to `msg.sender` by the same state change;
    ///      there is no separate bind transaction to front-run or later rebind.
    function fundDeal(uint256 dealId, bytes32 evaluatorPolicyCommitment) external payable {
        _fundDeal(dealId, evaluatorPolicyCommitment);
    }

    function _fundDeal(uint256 dealId, bytes32 evaluatorPolicyCommitment) internal {
        _requireProductionAttestationBinding();
        Deal storage d = _getExistingDeal(dealId);
        if (d.state != State.Created) revert InvalidState(State.Created, d.state);
        if (d.paymentToken != address(0)) revert TokenMismatch();
        if (block.timestamp >= d.expiry) revert AlreadyExpired();
        if (msg.value == 0 || msg.value < d.reservePrice) revert InsufficientFunding();
        if (evaluatorPolicyCommitment == bytes32(0)) revert ZeroEvaluatorPolicyCommitment();
        if ((productionRelease || approvalRequirementsFrozen) && !approvedEvaluatorPolicies[evaluatorPolicyCommitment]) revert EvaluatorPolicyNotApproved();

        d.buyer = msg.sender;
        d.budgetCap = msg.value;
        d.evaluatorPolicyCommitment = evaluatorPolicyCommitment;
        d.state = State.Funded;

        emit DealFunded(dealId, msg.sender, msg.value, address(0), evaluatorPolicyCommitment);
    }

    /// @notice Compatibility-only local ERC20 funding path.
    function fundDealERC20(uint256 dealId, uint256 amount) external nonReentrant {
        if (productionRelease) revert LegacyFundingUnavailable();
        _fundDealERC20(dealId, amount, LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT);
    }

    /// @notice Buyer atomically funds an ERC20-denominated deal and commits its
    ///         exact evaluator recipe. Caller must approve `amount` first.
    function fundDealERC20(uint256 dealId, uint256 amount, bytes32 evaluatorPolicyCommitment) external nonReentrant {
        _fundDealERC20(dealId, amount, evaluatorPolicyCommitment);
    }

    function _fundDealERC20(uint256 dealId, uint256 amount, bytes32 evaluatorPolicyCommitment) internal {
        _requireProductionAttestationBinding();
        Deal storage d = _getExistingDeal(dealId);
        if (d.state != State.Created) revert InvalidState(State.Created, d.state);
        if (d.paymentToken == address(0)) revert TokenMismatch();
        if (block.timestamp >= d.expiry) revert AlreadyExpired();
        if (amount == 0 || amount < d.reservePrice) revert InsufficientFunding();
        if (evaluatorPolicyCommitment == bytes32(0)) revert ZeroEvaluatorPolicyCommitment();
        if ((productionRelease || approvalRequirementsFrozen) && !approvedEvaluatorPolicies[evaluatorPolicyCommitment]) revert EvaluatorPolicyNotApproved();
        _requirePaymentToken(d.paymentToken);

        uint256 balanceBefore = _tokenBalance(d.paymentToken, address(this));

        // Effects before the external token pull (checks-effects-interactions).
        d.buyer = msg.sender;
        d.budgetCap = amount;
        d.evaluatorPolicyCommitment = evaluatorPolicyCommitment;
        d.state = State.Funded;

        _safeTransferFrom(d.paymentToken, msg.sender, address(this), amount);

        uint256 balanceAfter = _tokenBalance(d.paymentToken, address(this));
        if (balanceAfter < balanceBefore || balanceAfter - balanceBefore != amount) {
            revert TokenAmountMismatch();
        }

        emit DealFunded(dealId, msg.sender, amount, d.paymentToken, evaluatorPolicyCommitment);
    }

    // ── TEE submits evaluation result ──────────────────────────────────
    /// @notice TEE submits bounded evaluation result + public compute tariff.
    ///         The contract derives the canonical public result hash; the
    ///         result verifier authorizes that hash together with the TEE
    ///         identity, compose hash, score, cost, and expiry.
    /// @param dealId The deal being evaluated
    /// @param scoreBand Bounded score (enum, never raw metrics)
    /// @param computeCost Deterministic public tariff; raw metering stays in the TEE
    function submitResult(
        uint256 dealId,
        ScoreBand scoreBand,
        uint256 computeCost,
        bytes32 composeHash,
        uint256 resultAuthorizationExpiry,
        bytes32 attestationEvidenceHash,
        uint256 attestationAuthorizationExpiry,
        bytes calldata resultVerifierSignature,
        bytes calldata attestationVerifierSignature
    ) external {
        _requireProductionAttestationBinding();
        _requireFrozenResultAuthorizationBindings();
        Deal storage d = _getExistingDeal(dealId);
        if (d.state != State.Funded) revert InvalidState(State.Funded, d.state);
        if (msg.sender != d.teeIdentity) revert NotTEE();
        if (block.timestamp >= d.expiry) revert AlreadyExpired();
        if (composeHash == bytes32(0)) revert ZeroComposeHash();
        if (composeApprovalRequired && !approvedComposeHashes[composeHash]) {
            revert ComposeHashNotApproved();
        }
        // When identity binding is enforced, the submitting TEE identity may only
        // settle under the exact measurement governance registered for it.
        if (teeIdentityApprovalRequired && teeIdentityComposeHash[d.teeIdentity] != composeHash) {
            revert ComposeHashIdentityMismatch();
        }
        _requireFreshAuthorization(resultAuthorizationExpiry, false);
        _requireFreshAuthorization(attestationAuthorizationExpiry, true);
        if (attestationEvidenceHash == bytes32(0)) revert ZeroAttestationEvidenceHash();
        if (computeSettlementPolicyEnabled) {
            uint256 expectedComputeCost = _policyComputeCost(d.reservePrice, d.budgetCap);
            if (computeCost != expectedComputeCost) {
                revert ComputeSettlementPolicyMismatch(expectedComputeCost, computeCost);
            }
        }
        bytes32 resultHash = _canonicalResultHash(dealId, d, composeHash, scoreBand, computeCost);
        if (
            _recoverSignerOrZero(
                    _toEthSignedMessageHash(
                        _authorizationDigest(
                            dealId,
                            msg.sender,
                            composeHash,
                            d.evaluatorPolicyCommitment,
                            resultHash,
                            resultAuthorizationExpiry
                        )
                    ),
                    resultVerifierSignature
                ) != resultVerifier
        ) revert InvalidResultAuthorization();
        if (
            _recoverSignerOrZero(
                    _toEthSignedMessageHash(
                        _attestationAuthorizationDigest(
                            dealId,
                            msg.sender,
                            composeHash,
                            d.evaluatorPolicyCommitment,
                            resultHash,
                            attestationEvidenceHash,
                            attestationAuthorizationExpiry
                        )
                    ),
                    attestationVerifierSignature
                ) != attestationVerifier
        ) revert InvalidAttestationAuthorization();

        uint256 fee = _mulBps(computeCost, feeBps);
        if (computeCost + fee > d.budgetCap) revert ComputeCostOverBudget();

        d.scoreBand = scoreBand;
        d.computeCost = computeCost;
        d.fee = fee;
        d.resultHash = resultHash;
        d.resultComposeHash = composeHash;
        d.attestationEvidenceHash = attestationEvidenceHash;
        d.resultAuthorizationExpiry = resultAuthorizationExpiry;
        d.attestationAuthorizationExpiry = attestationAuthorizationExpiry;
        d.state = State.Evaluated;

        emit ResultAuthorized(
            dealId,
            resultVerifier,
            msg.sender,
            composeHash,
            d.evaluatorPolicyCommitment,
            attestationReleasePolicyHash,
            resultAuthorizationExpiry
        );
        emit AttestationAuthorized(
            dealId,
            attestationVerifier,
            attestationEvidenceHash,
            attestationReleasePolicyHash,
            attestationAuthorizationExpiry
        );
        emit EvaluationSubmitted(dealId, scoreBand, computeCost, resultHash);
    }

    function resultAuthorizationDigest(
        uint256 dealId,
        bytes32 composeHash,
        ScoreBand scoreBand,
        uint256 computeCost,
        uint256 authorizationExpiry
    ) external view returns (bytes32) {
        Deal storage d = _getExistingDeal(dealId);
        bytes32 resultHash = _canonicalResultHash(dealId, d, composeHash, scoreBand, computeCost);
        return _authorizationDigest(
            dealId, d.teeIdentity, composeHash, d.evaluatorPolicyCommitment, resultHash, authorizationExpiry
        );
    }

    /// @notice Digest the independent QVL must sign for the exact bounded
    ///         result and hash-only attestation evidence.
    function attestationAuthorizationDigest(
        uint256 dealId,
        bytes32 composeHash,
        ScoreBand scoreBand,
        uint256 computeCost,
        bytes32 attestationEvidenceHash,
        uint256 authorizationExpiry
    ) external view returns (bytes32) {
        Deal storage d = _getExistingDeal(dealId);
        bytes32 resultHash = _canonicalResultHash(dealId, d, composeHash, scoreBand, computeCost);
        return _attestationAuthorizationDigest(
            dealId,
            d.teeIdentity,
            composeHash,
            d.evaluatorPolicyCommitment,
            resultHash,
            attestationEvidenceHash,
            authorizationExpiry
        );
    }

    /// @notice Domain-separated canonical hash of the bounded public result.
    /// @dev Every field is either immutable after funding or a bounded,
    ///      verifier-authorized result field. No caller-provided opaque hash or
    ///      raw evaluator output is accepted by `submitResult`.
    function canonicalResultHash(uint256 dealId, bytes32 composeHash, ScoreBand scoreBand, uint256 computeCost)
        external
        view
        returns (bytes32)
    {
        Deal storage d = _getExistingDeal(dealId);
        return _canonicalResultHash(dealId, d, composeHash, scoreBand, computeCost);
    }

    // ── Buyer accepts — three-way settlement ───────────────────────────
    /// @notice Buyer accepts the evaluation and sets a deal payment.
    ///         Settlement: seller gets dealPayment, developer gets compute+fee,
    ///         buyer gets remainder.
    /// @param dealId The deal to accept
    /// @param dealPayment Amount to pay the seller (must be >= reservePrice, <= budgetCap)
    function acceptDeal(uint256 dealId, uint256 dealPayment) external {
        Deal storage d = _getExistingDeal(dealId);
        if (d.state != State.Evaluated) revert InvalidState(State.Evaluated, d.state);
        if (msg.sender != d.buyer) revert NotBuyer();
        if (dealPayment < d.reservePrice) revert PaymentBelowReserve();

        uint256 devPayment = d.computeCost + d.fee;
        uint256 totalOut = dealPayment + devPayment;
        if (totalOut > d.budgetCap) revert PaymentAboveBudget();

        d.state = State.Accepted;

        uint256 buyerRefund = d.budgetCap - totalOut;
        address token = d.paymentToken;
        _accruePayout(dealId, token, d.seller, dealPayment);
        _accruePayout(dealId, token, developer, devPayment);
        _accruePayout(dealId, token, d.buyer, buyerRefund);

        emit DealAccepted(dealId, dealPayment, devPayment, buyerRefund);
    }

    // ── Buyer rejects — two-way settlement ─────────────────────────────
    /// @notice Buyer rejects. Developer still gets compute+fee (training happened).
    ///         Buyer gets remainder. Seller gets nothing.
    function rejectDeal(uint256 dealId) external {
        Deal storage d = _getExistingDeal(dealId);
        if (d.state != State.Evaluated) revert InvalidState(State.Evaluated, d.state);
        if (msg.sender != d.buyer) revert NotBuyer();

        d.state = State.Rejected;

        uint256 devPayment = d.computeCost + d.fee;
        uint256 buyerRefund = d.budgetCap - devPayment;
        address token = d.paymentToken;
        _accruePayout(dealId, token, developer, devPayment);
        _accruePayout(dealId, token, d.buyer, buyerRefund);

        emit DealRejected(dealId, devPayment, buyerRefund);
    }

    // ── Expire — anyone can call after deadline ────────────────────────
    /// @notice Expire a deal after its deadline. Refunds buyer (minus any compute).
    function expireDeal(uint256 dealId) external {
        Deal storage d = _getExistingDeal(dealId);
        if (block.timestamp < d.expiry) revert NotExpired();
        if (d.state == State.Accepted || d.state == State.Rejected || d.state == State.Expired) {
            revert InvalidState(State.Funded, d.state);
        }

        State prev = d.state;
        d.state = State.Expired;

        if (prev == State.Created) {
            // No buyer yet — nothing to refund
            emit DealExpired(dealId, 0);
            return;
        }

        // Funded or Evaluated — refund buyer (minus compute if any)
        uint256 devPayment = d.computeCost + d.fee;
        uint256 refund = d.budgetCap - devPayment;
        address token = d.paymentToken;
        _accruePayout(dealId, token, developer, devPayment);
        _accruePayout(dealId, token, d.buyer, refund);

        emit DealExpired(dealId, refund);
    }

    /// @notice Withdraw claimable native-ETH proceeds from prior settlements.
    function withdraw() external nonReentrant {
        _withdraw(address(0));
    }

    /// @notice Withdraw claimable proceeds in a specific token (address(0)=ETH).
    function withdraw(address token) external nonReentrant {
        _withdraw(token);
    }

    function _withdraw(address token) internal {
        uint256 amount = pendingWithdrawals[token][msg.sender];
        if (amount == 0) revert NothingToWithdraw();

        pendingWithdrawals[token][msg.sender] = 0;

        if (token == address(0)) {
            (bool ok,) = msg.sender.call{value: amount}("");
            if (!ok) {
                pendingWithdrawals[token][msg.sender] = amount;
                revert TransferFailed();
            }
        } else {
            // A failed ERC20 transfer reverts the whole call, so the zeroed
            // balance is rolled back atomically — no manual restore needed.
            _safeTransfer(token, msg.sender, amount);
        }

        emit Withdrawal(msg.sender, token, amount);
    }

    // ── View helpers ───────────────────────────────────────────────────
    function getDeal(uint256 dealId) external view returns (Deal memory) {
        return _getExistingDeal(dealId);
    }

    function dealCount() external view returns (uint256) {
        return nextDealId;
    }

    function _requireProductionAttestationBinding() internal view {
        // Production posture is an immutable constructor input, not a mutable
        // post-deployment marker. This closes the deployment-to-configuration
        // transaction window in which a third party could otherwise create or
        // fund a deal before approvalRequirementsFrozen was set. Legacy/local
        // rooms remain usable only when explicitly deployed with `false`.
        if (
            (productionRelease || approvalRequirementsFrozen)
                && (!approvalRequirementsFrozen
                    || !attestationBindingFrozen
                    || resultVerifierFrozen == false
                    || resultVerifier == address(0)
                    || pendingResultVerifier != address(0)
                    || pendingResultVerifierActivatesAt != 0
                    || attestationVerifier == address(0)
                    || attestationReleasePolicyHash == bytes32(0)
                    || pendingAttestationVerifier != address(0)
                    || pendingAttestationReleasePolicyHash != bytes32(0)
                    || pendingAttestationBindingActivatesAt != 0
                    || !feeBpsFrozen
                    || pendingFeeBpsActivatesAt != 0
                    || !computeSettlementPolicyEnabled
                    || !composeApprovalRequired
                    || !teeIdentityApprovalRequired
                    || !composeAdditionsFrozen
                    || !teeIdentityAdditionsFrozen
                    || approvedComposeCount != 1
                    || approvedTeeIdentityCount != 1
                    || pendingComposeCount != 0
                    || pendingTeeIdentityCount != 0
                    || !evaluatorPolicySetFrozen
                    || approvedEvaluatorPolicyCount != REQUIRED_EVALUATOR_POLICY_COUNT
                    || pendingEvaluatorPolicyCount != 0
                    || evaluatorPolicySetRoot == bytes32(0))
        ) revert AttestationBindingNotReady();
    }

    function _requireFrozenResultAuthorizationBindings() internal view {
        if (
            !resultVerifierFrozen || !attestationBindingFrozen || resultVerifier == address(0)
                || attestationVerifier == address(0) || attestationReleasePolicyHash == bytes32(0)
        ) revert AttestationBindingNotReady();
        if (resultVerifier == attestationVerifier) revert RoleConflict();
    }

    function _requireFreshAuthorization(uint256 authorizationExpiry, bool attestationAuthorization) internal view {
        if (block.timestamp >= authorizationExpiry) {
            if (attestationAuthorization) revert AttestationAuthorizationExpired();
            revert AuthorizationExpired();
        }
        if (authorizationExpiry > block.timestamp + MAX_RESULT_AUTHORIZATION_LIFETIME) {
            revert AuthorizationLifetimeTooLong();
        }
    }

    function _getExistingDeal(uint256 dealId) internal view returns (Deal storage deal) {
        if (dealId >= nextDealId) revert DealNotFound();
        return deals[dealId];
    }

    function _accruePayout(uint256 dealId, address token, address recipient, uint256 amount) internal {
        if (amount == 0) return;

        pendingWithdrawals[token][recipient] += amount;
        emit PayoutAccrued(dealId, recipient, token, amount);
    }

    function _safeTransfer(address token, address to, uint256 amount) internal {
        _requirePaymentToken(token);
        uint256 senderBefore = _tokenBalance(token, address(this));
        uint256 recipientBefore = _tokenBalance(token, to);
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
        uint256 senderAfter = _tokenBalance(token, address(this));
        uint256 recipientAfter = _tokenBalance(token, to);
        if (
            senderAfter > senderBefore || senderBefore - senderAfter != amount || recipientAfter < recipientBefore
                || recipientAfter - recipientBefore != amount
        ) revert TokenAmountMismatch();
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }

    function _mulBps(uint256 value, uint256 bps) internal pure returns (uint256) {
        uint256 quotient = value / 10000;
        uint256 remainder = value % 10000;
        return (quotient * bps) + ((remainder * bps) / 10000);
    }

    function _policyComputeCost(uint256 reservePrice, uint256 budgetCap) internal view returns (uint256) {
        // COMPUTE_SETTLEMENT_BPS is exactly 1%, so division avoids a potentially
        // overflowing budgetCap * bps intermediate even for arbitrary ERC20 units.
        uint256 target = budgetCap / 100;
        uint256 available = budgetCap > reservePrice ? budgetCap - reservePrice : 0;
        uint256 denominator = 10000 + feeBps;
        // floor(available * 10000 / denominator), without an overflowing product.
        uint256 quotient = available / denominator;
        uint256 remainder = available % denominator;
        uint256 maximum = (quotient * 10000) + ((remainder * 10000) / denominator);
        return target < maximum ? target : maximum;
    }

    function _requirePaymentToken(address token) internal view {
        if (token == address(0) || token.code.length == 0) revert InvalidPaymentToken();
    }

    function _tokenBalance(address token, address account) internal view returns (uint256 balance) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSelector(IERC20.balanceOf.selector, account));
        if (!ok || data.length < 32) revert TransferFailed();
        balance = abi.decode(data, (uint256));
    }

    function _authorizationDigest(
        uint256 dealId,
        address teeIdentity,
        bytes32 composeHash,
        bytes32 evaluatorPolicyCommitment,
        bytes32 resultHash,
        uint256 authorizationExpiry
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                RESULT_AUTHORIZATION_TYPEHASH,
                block.chainid,
                address(this),
                dealId,
                teeIdentity,
                composeHash,
                evaluatorPolicyCommitment,
                resultHash,
                attestationReleasePolicyHash,
                authorizationExpiry
            )
        );
    }

    function _attestationAuthorizationDigest(
        uint256 dealId,
        address teeIdentity,
        bytes32 composeHash,
        bytes32 evaluatorPolicyCommitment,
        bytes32 resultHash,
        bytes32 attestationEvidenceHash,
        uint256 authorizationExpiry
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                ATTESTATION_AUTHORIZATION_TYPEHASH,
                block.chainid,
                address(this),
                dealId,
                teeIdentity,
                composeHash,
                evaluatorPolicyCommitment,
                resultHash,
                attestationReleasePolicyHash,
                attestationEvidenceHash,
                authorizationExpiry
            )
        );
    }

    function _canonicalResultHash(
        uint256 dealId,
        Deal storage d,
        bytes32 composeHash,
        ScoreBand scoreBand,
        uint256 computeCost
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                PUBLIC_RESULT_TYPEHASH,
                block.chainid,
                address(this),
                dealId,
                d.seller,
                d.buyer,
                d.reservePrice,
                d.budgetCap,
                d.expiry,
                d.artifactHash,
                d.teeIdentity,
                composeHash,
                d.evaluatorPolicyCommitment,
                uint8(scoreBand),
                computeCost
            )
        );
    }

    function _recoverSignerOrZero(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        if (uint256(s) == 0 || uint256(s) > SECP256K1_HALF_ORDER) {
            return address(0);
        }

        address signer = ecrecover(digest, v, r, s);
        return signer;
    }

    function _toEthSignedMessageHash(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }
}
