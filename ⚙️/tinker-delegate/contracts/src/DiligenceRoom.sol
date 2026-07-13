// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC20 surface used for stablecoin (e.g. USDC) settlement.
interface IERC20 {
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
        Created,     // Seller listed, awaiting buyer
        Funded,      // Buyer funded, awaiting TEE evaluation
        Evaluated,   // TEE submitted result, awaiting buyer decision
        Accepted,    // Buyer accepted — seller paid
        Rejected,    // Buyer rejected — seller gets nothing
        Expired      // Deadline passed — refund
    }

    // ── Score bands (bounded output — never raw scores) ────────────────
    enum ScoreBand {
        Negligible,  // <1% improvement
        Low,         // 1-5%
        Medium,      // 5-10%
        High,        // 10-20%
        Exceptional  // >20%
    }

    // ── Deal storage ───────────────────────────────────────────────────
    struct Deal {
        address seller;
        address buyer;
        uint256 reservePrice;      // min payment seller will accept (wei)
        uint256 budgetCap;         // max buyer will pay (wei)
        uint256 expiry;            // unix timestamp
        State state;
        bytes32 artifactHash;      // keccak256 of encrypted artifact
        address teeIdentity;       // TEE-derived address (from KMS key)
        // Evaluation result (set by TEE)
        ScoreBand scoreBand;
        uint256 computeCost;       // Tinker compute cost reported by TEE
        uint256 fee;               // 1% surcharge
        bytes32 resultHash;        // keccak256 of full EvaluationResult
        bytes32 resultComposeHash; // verified compose/app measurement binding
        // Appended last so the positional `deals()` decode of the leading
        // fields (used by the off-chain submitter) is unchanged.
        address paymentToken;      // address(0) = native ETH, else ERC20 token
    }

    // ── Constants ──────────────────────────────────────────────────────
    uint256 public constant DEFAULT_FEE_BPS = 100;  // 1% = 100 basis points
    uint256 public constant MAX_FEE_BPS = 1000;     // hard cap: 10%
    uint256 public constant FEE_TIMELOCK_DELAY = 2 days;
    bytes32 public constant RESULT_AUTHORIZATION_TYPEHASH = keccak256(
        "DiligenceRoomResultAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,uint8 scoreBand,uint256 computeCost,bytes32 resultHash,uint256 authorizationExpiry)"
    );

    // ── State ──────────────────────────────────────────────────────────
    address public immutable developer;
    address public immutable resultVerifier;
    mapping(uint256 => Deal) public deals;
    // token (address(0)=ETH) => recipient => claimable amount
    mapping(address => mapping(address => uint256)) public pendingWithdrawals;
    uint256 public nextDealId;

    // Protocol fee (basis points of metered compute cost), governed by a
    // timelock and permanently freezable. The fee applied to a deal is locked at
    // submitResult time (stored on the Deal), so a later change never retroacts
    // on already-evaluated deals. Default 1%; capped at MAX_FEE_BPS.
    uint256 public feeBps = DEFAULT_FEE_BPS;
    uint256 public pendingFeeBps;
    uint256 public pendingFeeBpsActivatesAt;
    bool public feeBpsFrozen;

    // On-chain governance of attested TEE measurements. When
    // `composeApprovalRequired` is enabled, submitResult also requires the
    // authorized composeHash to be developer-approved on-chain, so a result
    // cannot settle from a measurement that governance has not admitted — even
    // if the off-chain resultVerifier signs it. Default false preserves the
    // verifier-signature-only path; production deployments enable it to bind
    // teeIdentity to a governance-approved compose/app measurement.
    mapping(bytes32 => bool) public approvedComposeHashes;
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
    bool public teeIdentityApprovalRequired;

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
        address paymentToken
    );
    event EvaluationSubmitted(
        uint256 indexed dealId,
        ScoreBand scoreBand,
        uint256 computeCost,
        bytes32 resultHash
    );
    event ResultAuthorized(
        uint256 indexed dealId,
        address indexed verifier,
        address indexed teeIdentity,
        bytes32 composeHash,
        uint256 authorizationExpiry
    );
    event DealAccepted(
        uint256 indexed dealId,
        uint256 sellerPayment,
        uint256 devPayment,
        uint256 buyerRefund
    );
    event DealRejected(
        uint256 indexed dealId,
        uint256 devPayment,
        uint256 buyerRefund
    );
    event DealExpired(uint256 indexed dealId, uint256 refund);
    event PayoutAccrued(uint256 indexed dealId, address indexed recipient, address token, uint256 amount);
    event Withdrawal(address indexed recipient, address token, uint256 amount);
    event ComposeHashApproved(bytes32 indexed composeHash);
    event ComposeHashRevoked(bytes32 indexed composeHash);
    event ComposeApprovalRequirementSet(bool required);
    event TeeIdentityApproved(address indexed teeIdentity, bytes32 composeHash);
    event TeeIdentityRevoked(address indexed teeIdentity);
    event TeeIdentityApprovalRequirementSet(bool required);
    event FeeBpsProposed(uint256 newFeeBps, uint256 activatesAt);
    event FeeBpsActivated(uint256 newFeeBps);
    event FeeBpsProposalCancelled(uint256 proposedFeeBps);
    event FeeBpsFrozen(uint256 finalFeeBps);

    // ── Errors ─────────────────────────────────────────────────────────
    error InvalidState(State expected, State actual);
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
    error ZeroComposeHash();
    error AuthorizationExpired();
    error InvalidResultAuthorization();
    error NotDeveloper();
    error ComposeHashNotApproved();
    error TeeIdentityNotApproved();
    error ComposeHashIdentityMismatch();
    error FeeBpsFrozenError();
    error FeeBpsTooHigh();
    error NoFeeBpsPending();
    error FeeBpsProposalExists();
    error FeeActivationTooEarly(uint256 activatesAt);

    // ── Constructor ────────────────────────────────────────────────────
    constructor(address _resultVerifier) {
        if (_resultVerifier == address(0)) revert ZeroResultVerifier();
        developer = msg.sender;
        resultVerifier = _resultVerifier;
    }

    // ── Developer governs approved TEE measurements ────────────────────
    /// @notice Approve a compose hash as an admitted attested measurement.
    function approveComposeHash(bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (composeHash == bytes32(0)) revert ZeroComposeHash();
        approvedComposeHashes[composeHash] = true;
        emit ComposeHashApproved(composeHash);
    }

    /// @notice Revoke a previously approved compose hash (e.g. after a rebuild).
    function revokeComposeHash(bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        approvedComposeHashes[composeHash] = false;
        emit ComposeHashRevoked(composeHash);
    }

    /// @notice Enable/disable the on-chain compose-approval gate on submitResult.
    function setComposeApprovalRequired(bool required) external {
        if (msg.sender != developer) revert NotDeveloper();
        composeApprovalRequired = required;
        emit ComposeApprovalRequirementSet(required);
    }

    /// @notice Bind a TEE identity address to an attested compose measurement.
    function approveTeeIdentity(address teeIdentity, bytes32 composeHash) external {
        if (msg.sender != developer) revert NotDeveloper();
        if (teeIdentity == address(0)) revert ZeroTEEIdentity();
        if (composeHash == bytes32(0)) revert ZeroComposeHash();
        teeIdentityComposeHash[teeIdentity] = composeHash;
        emit TeeIdentityApproved(teeIdentity, composeHash);
    }

    /// @notice Revoke a TEE identity binding (e.g. rotated key or retired image).
    function revokeTeeIdentity(address teeIdentity) external {
        if (msg.sender != developer) revert NotDeveloper();
        teeIdentityComposeHash[teeIdentity] = bytes32(0);
        emit TeeIdentityRevoked(teeIdentity);
    }

    /// @notice Enable/disable the on-chain TEE-identity binding gate.
    function setTeeIdentityApprovalRequired(bool required) external {
        if (msg.sender != developer) revert NotDeveloper();
        teeIdentityApprovalRequired = required;
        emit TeeIdentityApprovalRequirementSet(required);
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

    // ── Seller creates deal ────────────────────────────────────────────
    /// @notice Seller lists an artifact for evaluation
    /// @param reservePrice Minimum payment the seller will accept (wei)
    /// @param expiry Unix timestamp after which deal can be expired
    /// @param artifactHash keccak256 of the encrypted artifact
    /// @param teeIdentity Address derived from TEE's KMS key
    function createDeal(
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity
    ) external returns (uint256 dealId) {
        return _createDeal(reservePrice, expiry, artifactHash, teeIdentity, address(0));
    }

    /// @notice Seller lists an artifact for evaluation settled in an ERC20 token.
    /// @param paymentToken ERC20 token address (address(0) means native ETH)
    function createDeal(
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity,
        address paymentToken
    ) external returns (uint256 dealId) {
        return _createDeal(reservePrice, expiry, artifactHash, teeIdentity, paymentToken);
    }

    function _createDeal(
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity,
        address paymentToken
    ) internal returns (uint256 dealId) {
        if (expiry <= block.timestamp) revert InvalidExpiry();
        if (artifactHash == bytes32(0)) revert ZeroArtifactHash();
        if (teeIdentity == address(0)) revert ZeroTEEIdentity();
        if (teeIdentityApprovalRequired && teeIdentityComposeHash[teeIdentity] == bytes32(0)) {
            revert TeeIdentityNotApproved();
        }

        dealId = nextDealId++;
        Deal storage d = deals[dealId];
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
    /// @notice Buyer funds the deal. msg.value covers budget_cap.
    ///         Compute cost + fee are deducted from this on settlement.
    function fundDeal(uint256 dealId) external payable {
        Deal storage d = deals[dealId];
        if (d.state != State.Created) revert InvalidState(State.Created, d.state);
        if (d.paymentToken != address(0)) revert TokenMismatch();
        if (block.timestamp >= d.expiry) revert AlreadyExpired();
        if (msg.value == 0) revert InsufficientFunding();

        d.buyer = msg.sender;
        d.budgetCap = msg.value;
        d.state = State.Funded;

        emit DealFunded(dealId, msg.sender, msg.value, address(0));
    }

    /// @notice Buyer funds an ERC20-denominated deal. Caller must have approved
    ///         `amount` of the deal's `paymentToken` to this contract first.
    function fundDealERC20(uint256 dealId, uint256 amount) external {
        Deal storage d = deals[dealId];
        if (d.state != State.Created) revert InvalidState(State.Created, d.state);
        if (d.paymentToken == address(0)) revert TokenMismatch();
        if (block.timestamp >= d.expiry) revert AlreadyExpired();
        if (amount == 0) revert InsufficientFunding();

        // Effects before the external token pull (checks-effects-interactions).
        d.buyer = msg.sender;
        d.budgetCap = amount;
        d.state = State.Funded;

        _safeTransferFrom(d.paymentToken, msg.sender, address(this), amount);

        emit DealFunded(dealId, msg.sender, amount, d.paymentToken);
    }

    // ── TEE submits evaluation result ──────────────────────────────────
    /// @notice TEE submits bounded evaluation result + metered compute cost.
    ///         The result must be authorized by resultVerifier over the TEE
    ///         identity, compose hash, result hash, score, cost, and expiry.
    /// @param dealId The deal being evaluated
    /// @param scoreBand Bounded score (enum, never raw metrics)
    /// @param computeCost Actual Tinker API cost in wei
    /// @param resultHash keccak256 of the full EvaluationResult struct
    function submitResult(
        uint256 dealId,
        ScoreBand scoreBand,
        uint256 computeCost,
        bytes32 resultHash,
        bytes32 composeHash,
        uint256 authorizationExpiry,
        bytes calldata verifierSignature
    ) external {
        Deal storage d = deals[dealId];
        if (d.state != State.Funded) revert InvalidState(State.Funded, d.state);
        if (msg.sender != d.teeIdentity) revert NotTEE();
        if (block.timestamp >= d.expiry) revert AlreadyExpired();
        if (composeHash == bytes32(0)) revert ZeroComposeHash();
        if (composeApprovalRequired && !approvedComposeHashes[composeHash]) {
            revert ComposeHashNotApproved();
        }
        // When identity binding is enforced, the submitting TEE identity may only
        // settle under the exact measurement governance registered for it.
        if (
            teeIdentityApprovalRequired
            && teeIdentityComposeHash[d.teeIdentity] != composeHash
        ) {
            revert ComposeHashIdentityMismatch();
        }
        if (block.timestamp > authorizationExpiry) revert AuthorizationExpired();
        if (
            _recoverSigner(
                _toEthSignedMessageHash(
                    _authorizationDigest(
                        dealId,
                        msg.sender,
                        composeHash,
                        scoreBand,
                        computeCost,
                        resultHash,
                        authorizationExpiry
                    )
                ),
                verifierSignature
            ) != resultVerifier
        ) revert InvalidResultAuthorization();

        uint256 fee = (computeCost * feeBps) / 10000;
        if (computeCost + fee > d.budgetCap) revert ComputeCostOverBudget();

        d.scoreBand = scoreBand;
        d.computeCost = computeCost;
        d.fee = fee;
        d.resultHash = resultHash;
        d.resultComposeHash = composeHash;
        d.state = State.Evaluated;

        emit ResultAuthorized(dealId, resultVerifier, msg.sender, composeHash, authorizationExpiry);
        emit EvaluationSubmitted(dealId, scoreBand, computeCost, resultHash);
    }

    function resultAuthorizationDigest(
        uint256 dealId,
        address teeIdentity,
        bytes32 composeHash,
        ScoreBand scoreBand,
        uint256 computeCost,
        bytes32 resultHash,
        uint256 authorizationExpiry
    ) external view returns (bytes32) {
        return _authorizationDigest(
            dealId,
            teeIdentity,
            composeHash,
            scoreBand,
            computeCost,
            resultHash,
            authorizationExpiry
        );
    }

    // ── Buyer accepts — three-way settlement ───────────────────────────
    /// @notice Buyer accepts the evaluation and sets a deal payment.
    ///         Settlement: seller gets dealPayment, developer gets compute+fee,
    ///         buyer gets remainder.
    /// @param dealId The deal to accept
    /// @param dealPayment Amount to pay the seller (must be >= reservePrice, <= budgetCap)
    function acceptDeal(uint256 dealId, uint256 dealPayment) external {
        Deal storage d = deals[dealId];
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
        Deal storage d = deals[dealId];
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
        Deal storage d = deals[dealId];
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
    function withdraw() external {
        _withdraw(address(0));
    }

    /// @notice Withdraw claimable proceeds in a specific token (address(0)=ETH).
    function withdraw(address token) external {
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
        return deals[dealId];
    }

    function dealCount() external view returns (uint256) {
        return nextDealId;
    }

    function _accruePayout(uint256 dealId, address token, address recipient, uint256 amount) internal {
        if (amount == 0) return;

        pendingWithdrawals[token][recipient] += amount;
        emit PayoutAccrued(dealId, recipient, token, amount);
    }

    function _safeTransfer(address token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }

    function _authorizationDigest(
        uint256 dealId,
        address teeIdentity,
        bytes32 composeHash,
        ScoreBand scoreBand,
        uint256 computeCost,
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
                uint8(scoreBand),
                computeCost,
                resultHash,
                authorizationExpiry
            )
        );
    }

    function _recoverSigner(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidResultAuthorization();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidResultAuthorization();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidResultAuthorization();
        return signer;
    }

    function _toEthSignedMessageHash(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }
}
