// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "./interfaces/IERC20.sol";
import { TokenTransfers } from "./lib/TokenTransfers.sol";

/// Holds the Refraction prize pool and decides who solved it first.
///
/// The hard part of paying for an answer on a public chain is that the answer
/// stops being secret the moment it is broadcast. A plain "submit the solution"
/// contest is decided by whoever watches the mempool and pays the most gas, not
/// by whoever solved it.
///
/// So entering takes two transactions. First a commitment, which is a hash over
/// the answer, the solver's own address and a salt. It discloses nothing, and it
/// cannot be produced by someone who does not already know the answer, so
/// nobody can squat a place in the queue before solving. Copying someone else's
/// commitment is useless: it is bound to their address, and the same bytes
/// submitted by anyone else can never be opened.
///
/// Then a reveal, which proves the commitment and takes the next unclaimed
/// place. Ranks, timings and awards all land in storage, so the leaderboard is
/// read from the chain rather than from us.
///
/// There is no owner who can pick a winner, change an award, or pay someone who
/// did not solve it. The single administrative power is reclaiming whatever is
/// still unclaimed after the deadline, so an unsolved puzzle does not lock the
/// tokens up forever.
contract RefractionPrizeV1 {
    using TokenTransfers for IERC20;

    error AlreadyCommitted();
    error AlreadySolved();
    error CommitmentTooNew();
    error DeadlinePassed();
    error DeadlineNotReached();
    error InvalidCommitment();
    error NoCommitment();
    error NotTreasury();
    error PrizesGone();
    error WrongAnswer();
    error ZeroAddress();

    event Committed(address indexed solver, bytes32 commitment, uint64 blockNumber);
    event Solved(address indexed solver, uint8 place, uint256 award, uint64 blockNumber);
    event Reclaimed(uint256 amount);

    /// A commitment has to be at least this old before it can be opened. One
    /// block is enough: it stops a watcher from seeing a reveal and landing its
    /// own commit-and-reveal pair alongside it in the same block.
    uint64 public constant COMMITMENT_AGE = 1;

    IERC20 public immutable token;
    /// keccak256 of the solution. The answer itself is never on chain until a
    /// winner reveals it, at which point the race is already decided.
    bytes32 public immutable answerHash;
    /// Where anything unclaimed goes after the deadline.
    address public immutable treasury;
    uint64 public immutable deadline;

    /// First, second and third. Fixed at deployment so nobody has to trust that
    /// the pool still holds what it promised.
    uint256[3] public awards;

    struct Entry {
        bytes32 commitment;
        uint64 committedAt;
        bool solved;
    }

    struct Winner {
        address solver;
        uint64 revealedAt;
        uint256 award;
    }

    mapping(address => Entry) public entries;
    Winner[] private board;

    /// How many addresses have committed. A commitment is proof its author has
    /// the answer, so this is an honest public read on how close the puzzle is
    /// to being finished, without disclosing anything about the solution.
    uint64 public commitments;

    constructor(
        IERC20 prizeToken,
        bytes32 solutionHash,
        address prizeTreasury,
        uint64 claimDeadline,
        uint256[3] memory prizeAwards
    ) {
        if (address(prizeToken) == address(0) || prizeTreasury == address(0)) revert ZeroAddress();
        token = prizeToken;
        answerHash = solutionHash;
        treasury = prizeTreasury;
        deadline = claimDeadline;
        awards = prizeAwards;
    }

    /// `keccak256(abi.encode(answer, msg.sender, salt))`.
    ///
    /// Reproduce it exactly, including the sender, or the reveal cannot open it.
    function commit(bytes32 commitment) external {
        if (block.timestamp > deadline) revert DeadlinePassed();
        if (board.length >= awards.length) revert PrizesGone();
        Entry storage entry = entries[msg.sender];
        if (entry.commitment != bytes32(0)) revert AlreadyCommitted();
        entry.commitment = commitment;
        entry.committedAt = uint64(block.number);
        commitments += 1;
        emit Committed(msg.sender, commitment, uint64(block.number));
    }

    /// Opens a commitment and takes the next unclaimed place.
    function reveal(string calldata answer, bytes32 salt) external {
        if (block.timestamp > deadline) revert DeadlinePassed();
        uint256 place = board.length;
        if (place >= awards.length) revert PrizesGone();

        Entry storage entry = entries[msg.sender];
        if (entry.commitment == bytes32(0)) revert NoCommitment();
        if (entry.solved) revert AlreadySolved();
        if (block.number < entry.committedAt + COMMITMENT_AGE) revert CommitmentTooNew();
        if (keccak256(bytes(answer)) != answerHash) revert WrongAnswer();
        if (keccak256(abi.encode(answer, msg.sender, salt)) != entry.commitment) {
            revert InvalidCommitment();
        }

        entry.solved = true;
        uint256 award = awards[place];
        board.push(Winner({ solver: msg.sender, revealedAt: uint64(block.number), award: award }));
        emit Solved(msg.sender, uint8(place + 1), award, uint64(block.number));
        token.push(msg.sender, award);
    }

    /// The whole leaderboard, in the order it was won.
    function leaderboard() external view returns (Winner[] memory) {
        return board;
    }

    function winnerCount() external view returns (uint256) {
        return board.length;
    }

    /// What the next solver takes, or zero once all three are gone.
    function nextAward() external view returns (uint256) {
        return board.length >= awards.length ? 0 : awards[board.length];
    }

    function reclaim() external {
        if (msg.sender != treasury) revert NotTreasury();
        if (block.timestamp <= deadline) revert DeadlineNotReached();
        uint256 unclaimed = 0;
        uint256 awardCount = awards.length;
        for (uint256 place = board.length; place < awardCount; place += 1) {
            unclaimed += awards[place];
        }
        emit Reclaimed(unclaimed);
        token.push(treasury, unclaimed);
    }
}
