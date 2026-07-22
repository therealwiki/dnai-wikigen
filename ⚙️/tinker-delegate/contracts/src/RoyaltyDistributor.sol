// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC20 surface used for stablecoin (e.g. USDC) settlement.
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title RoyaltyDistributor — on-chain pull-payment rail for per-query royalties
/// @notice The on-chain counterpart of the off-chain `royalty_settlement.RoyaltyLedger`.
///         A distributor deposits a per-query royalty total together with the
///         conserving per-owner split computed off-chain (`split_royalty`); the
///         contract credits each co-owner's claimable balance and lets owners
///         pull their funds. Settles in native ETH (`token == address(0)`) or an
///         ERC20. Conservation is enforced: the deposited total must equal the
///         sum of the per-owner amounts, and ERC20 balance deltas must match on
///         both ingress and withdrawal. Tokens with fees, rebases, or dishonest
///         balance reporting are rejected rather than silently short-paying.
contract RoyaltyDistributor {
    // token (address(0)=ETH) => owner => claimable amount
    mapping(address => mapping(address => uint256)) public pending;
    // A query may settle exactly once per distributor, regardless of settlement
    // token. The distributor address is part of the replay domain so an
    // unrelated caller cannot front-run a public query reference and consume it.
    mapping(address => mapping(bytes32 => bool)) public processedQueries;

    uint256 private _reentrancyLock = 1;

    event RoyaltyDistributed(
        address indexed distributor, bytes32 indexed queryRef, address indexed token, uint256 total, uint256 ownerCount
    );
    event RoyaltyAccrued(address indexed token, address indexed owner, uint256 amount);
    event RoyaltyWithdrawn(address indexed owner, address indexed token, uint256 amount);

    error LengthMismatch();
    error EmptyDistribution();
    error ZeroOwner();
    error SelfOwner();
    error ZeroAmount();
    error ZeroQueryRef();
    error ValueMismatch();
    error NothingToWithdraw();
    error TransferFailed();
    error InvalidToken();
    error TokenAmountMismatch();
    error QueryAlreadyProcessed();
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

    /// @notice Distribute a native-ETH royalty across co-owners. `msg.value` must
    ///         equal the sum of `amounts`.
    function distributeNative(bytes32 queryRef, address[] calldata owners, uint256[] calldata amounts)
        external
        payable
    {
        uint256 total = _credit(address(0), queryRef, owners, amounts);
        if (msg.value != total) revert ValueMismatch();
    }

    /// @notice Distribute an ERC20 royalty across co-owners. The caller must have
    ///         approved `sum(amounts)` of `token` to this contract.
    function distributeERC20(bytes32 queryRef, address token, address[] calldata owners, uint256[] calldata amounts)
        external
        nonReentrant
    {
        // Non-payable: the EVM already rejects any attached ETH.
        _requireToken(token);
        uint256 balanceBefore = _tokenBalance(token, address(this));
        uint256 total = _credit(token, queryRef, owners, amounts);
        _safeTransferFrom(token, msg.sender, address(this), total);
        uint256 balanceAfter = _tokenBalance(token, address(this));
        if (balanceAfter < balanceBefore || balanceAfter - balanceBefore != total) {
            revert TokenAmountMismatch();
        }
    }

    /// @notice Withdraw claimable native-ETH royalties.
    function withdraw() external nonReentrant {
        _withdraw(address(0));
    }

    /// @notice Withdraw claimable ERC20 royalties for `token`.
    function withdraw(address token) external nonReentrant {
        _withdraw(token);
    }

    function _credit(address token, bytes32 queryRef, address[] calldata owners, uint256[] calldata amounts)
        internal
        returns (uint256 total)
    {
        if (queryRef == bytes32(0)) revert ZeroQueryRef();
        if (processedQueries[msg.sender][queryRef]) revert QueryAlreadyProcessed();
        processedQueries[msg.sender][queryRef] = true;

        uint256 n = owners.length;
        if (n != amounts.length) revert LengthMismatch();
        if (n == 0) revert EmptyDistribution();
        for (uint256 i = 0; i < n; i++) {
            address owner = owners[i];
            uint256 amount = amounts[i];
            if (owner == address(0)) revert ZeroOwner();
            if (owner == address(this)) revert SelfOwner();
            if (amount == 0) revert ZeroAmount();
            pending[token][owner] += amount;
            total += amount;
            emit RoyaltyAccrued(token, owner, amount);
        }
        emit RoyaltyDistributed(msg.sender, queryRef, token, total, n);
    }

    function _withdraw(address token) internal {
        uint256 amount = pending[token][msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        pending[token][msg.sender] = 0; // effects before interaction
        if (token == address(0)) {
            (bool ok,) = msg.sender.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(token, msg.sender, amount);
        }
        emit RoyaltyWithdrawn(msg.sender, token, amount);
    }

    function _safeTransfer(address token, address to, uint256 amount) internal {
        _requireToken(token);
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

    function _requireToken(address token) internal view {
        if (token == address(0) || token.code.length == 0) revert InvalidToken();
    }

    function _tokenBalance(address token, address account) internal view returns (uint256 balance) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSelector(IERC20.balanceOf.selector, account));
        if (!ok || data.length < 32) revert TransferFailed();
        balance = abi.decode(data, (uint256));
    }
}
