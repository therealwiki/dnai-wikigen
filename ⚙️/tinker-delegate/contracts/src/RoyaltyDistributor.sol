// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC20 surface used for stablecoin (e.g. USDC) settlement.
interface IERC20 {
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
///         sum of the per-owner amounts, so no wei is created, stuck, or lost.
contract RoyaltyDistributor {
    // token (address(0)=ETH) => owner => claimable amount
    mapping(address => mapping(address => uint256)) public pending;

    event RoyaltyDistributed(bytes32 indexed queryRef, address indexed token, uint256 total, uint256 ownerCount);
    event RoyaltyAccrued(address indexed token, address indexed owner, uint256 amount);
    event RoyaltyWithdrawn(address indexed owner, address indexed token, uint256 amount);

    error LengthMismatch();
    error EmptyDistribution();
    error ZeroOwner();
    error ZeroAmount();
    error ValueMismatch();
    error NothingToWithdraw();
    error TransferFailed();

    /// @notice Distribute a native-ETH royalty across co-owners. `msg.value` must
    ///         equal the sum of `amounts`.
    function distributeNative(
        bytes32 queryRef,
        address[] calldata owners,
        uint256[] calldata amounts
    ) external payable {
        uint256 total = _credit(address(0), queryRef, owners, amounts);
        if (msg.value != total) revert ValueMismatch();
    }

    /// @notice Distribute an ERC20 royalty across co-owners. The caller must have
    ///         approved `sum(amounts)` of `token` to this contract.
    function distributeERC20(
        bytes32 queryRef,
        address token,
        address[] calldata owners,
        uint256[] calldata amounts
    ) external {
        // Non-payable: the EVM already rejects any attached ETH.
        uint256 total = _credit(token, queryRef, owners, amounts);
        _safeTransferFrom(token, msg.sender, address(this), total);
    }

    /// @notice Withdraw claimable native-ETH royalties.
    function withdraw() external {
        _withdraw(address(0));
    }

    /// @notice Withdraw claimable ERC20 royalties for `token`.
    function withdraw(address token) external {
        _withdraw(token);
    }

    function _credit(
        address token,
        bytes32 queryRef,
        address[] calldata owners,
        uint256[] calldata amounts
    ) internal returns (uint256 total) {
        uint256 n = owners.length;
        if (n != amounts.length) revert LengthMismatch();
        if (n == 0) revert EmptyDistribution();
        for (uint256 i = 0; i < n; i++) {
            address owner = owners[i];
            uint256 amount = amounts[i];
            if (owner == address(0)) revert ZeroOwner();
            if (amount == 0) revert ZeroAmount();
            pending[token][owner] += amount;
            total += amount;
            emit RoyaltyAccrued(token, owner, amount);
        }
        emit RoyaltyDistributed(queryRef, token, total, n);
    }

    function _withdraw(address token) internal {
        uint256 amount = pending[token][msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        pending[token][msg.sender] = 0; // effects before interaction
        if (token == address(0)) {
            (bool ok, ) = msg.sender.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(token, msg.sender, amount);
        }
        emit RoyaltyWithdrawn(msg.sender, token, amount);
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
}
