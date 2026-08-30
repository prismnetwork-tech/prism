// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "./interfaces/IERC20.sol";
import { TokenTransfers } from "./lib/TokenTransfers.sol";

/// Locks PRISM so the network can price compute lower for the people holding
/// it. The discount itself is applied off-chain when a lease is quoted; this
/// contract only answers one question, honestly and cheaply: how much has this
/// address had locked, and for how long.
///
/// There is deliberately no owner, no pause, no upgrade path and no way for
/// anyone but the staker to move a staked balance. A contract that can seize
/// deposits is not somewhere anyone should lock a token to save money on GPUs.
contract PrismStakeV1 {
    using TokenTransfers for IERC20;

    /// Stake has to be this old before it counts toward a discount. Without it,
    /// a borrowed balance could be staked, used to price one lease, and
    /// returned in the same block.
    uint64 public constant MATURITY = 24 hours;

    /// Withdrawals wait this long after being requested, so leaving is a
    /// decision rather than something that happens between a quote and its
    /// funding transaction.
    uint64 public constant COOLDOWN = 7 days;

    IERC20 public immutable token;

    struct Position {
        uint128 staked;
        uint128 unbonding;
        /// When the current staked balance became eligible. Adding to a
        /// position restarts it, so topping up cannot backdate maturity.
        uint64 maturesAt;
        uint64 withdrawableAt;
    }

    mapping(address => Position) private positions;

    uint256 public totalStaked;

    event Staked(address indexed account, uint256 amount, uint64 maturesAt);
    event Unbonding(address indexed account, uint256 amount, uint64 withdrawableAt);
    event Withdrawn(address indexed account, uint256 amount);

    error AmountZero();
    error AmountTooLarge();
    error InsufficientStake();
    error NothingUnbonding();
    error CooldownActive();
    error TokenZero();

    constructor(address token_) {
        if (token_ == address(0)) revert TokenZero();
        token = IERC20(token_);
    }

    function stake(uint256 amount) external {
        if (amount == 0) revert AmountZero();
        if (amount > type(uint128).max) revert AmountTooLarge();
        Position storage position = positions[msg.sender];
        position.staked += uint128(amount);
        position.maturesAt = uint64(block.timestamp) + MATURITY;
        totalStaked += amount;

        token.pull(msg.sender, amount);

        emit Staked(msg.sender, amount, position.maturesAt);
    }

    /// Moves stake into unbonding. It stops counting toward a discount
    /// immediately, which is the honest ordering: the benefit ends when the
    /// commitment does, not when the tokens land back in the wallet.
    function unstake(uint256 amount) external {
        if (amount == 0) revert AmountZero();
        Position storage position = positions[msg.sender];
        if (position.staked < amount) revert InsufficientStake();

        position.staked -= uint128(amount);
        position.unbonding += uint128(amount);
        position.withdrawableAt = uint64(block.timestamp) + COOLDOWN;
        totalStaked -= amount;

        emit Unbonding(msg.sender, amount, position.withdrawableAt);
    }

    function withdraw() external {
        Position storage position = positions[msg.sender];
        uint256 amount = position.unbonding;
        if (amount == 0) revert NothingUnbonding();
        if (block.timestamp < position.withdrawableAt) revert CooldownActive();

        position.unbonding = 0;
        position.withdrawableAt = 0;

        token.push(msg.sender, amount);

        emit Withdrawn(msg.sender, amount);
    }

    /// What the control plane prices against. Zero until the stake matures, so
    /// this is the number a discount may be derived from.
    function eligibleStakeOf(address account) external view returns (uint256) {
        Position storage position = positions[account];
        if (block.timestamp < position.maturesAt) return 0;
        return position.staked;
    }

    function positionOf(address account)
        external
        view
        returns (uint256 staked, uint256 unbonding, uint64 maturesAt, uint64 withdrawableAt)
    {
        Position storage position = positions[account];
        return (position.staked, position.unbonding, position.maturesAt, position.withdrawableAt);
    }
}
