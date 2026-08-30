// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "../src/interfaces/IERC20.sol";
import { RefractionPrizeV1 } from "../src/RefractionPrizeV1.sol";

contract MockPrism is IERC20 {
    mapping(address account => uint256) public balanceOf;
    mapping(address owner => mapping(address spender => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 approved = allowance[from][msg.sender];
        if (approved != type(uint256).max) allowance[from][msg.sender] = approved - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) private {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract RefractionPrizeV1Test {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);
    address private constant CAROL = address(0xCAC01);
    address private constant DAN = address(0xDA);
    address private constant BOT = address(0xB07);
    address private constant TREASURY = address(0x7);

    string private constant ANSWER = "refraction-splits-one-beam-into-many";
    uint64 private constant DEADLINE = 1_800_000_000;

    MockPrism private prism;
    RefractionPrizeV1 private prize;

    function setUp() public {
        prism = new MockPrism();
        prize = new RefractionPrizeV1(
            IERC20(address(prism)),
            keccak256(bytes(ANSWER)),
            TREASURY,
            DEADLINE,
            [uint256(3_000_000e18), uint256(2_000_000e18), uint256(1_000_000e18)]
        );
        prism.mint(address(prize), 6_000_000e18);
        VM.warp(DEADLINE - 30 days);
        VM.roll(100);
    }

    function _commitment(string memory answer, address solver, bytes32 salt)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(answer, solver, salt));
    }

    function _solve(address solver, bytes32 salt) private {
        VM.prank(solver);
        prize.commit(_commitment(ANSWER, solver, salt));
        VM.roll(block.number + 1);
        VM.prank(solver);
        prize.reveal(ANSWER, salt);
    }

    function _revealReverts(address solver, string memory answer, bytes32 salt)
        private
        returns (bool)
    {
        VM.prank(solver);
        (bool ok,) = address(prize).call(abi.encodeCall(RefractionPrizeV1.reveal, (answer, salt)));
        return !ok;
    }

    function test_three_places_pay_in_order() public {
        _solve(ALICE, bytes32("a"));
        _solve(BOB, bytes32("b"));
        _solve(CAROL, bytes32("c"));

        require(prism.balanceOf(ALICE) == 3_000_000e18, "first takes 3M");
        require(prism.balanceOf(BOB) == 2_000_000e18, "second takes 2M");
        require(prism.balanceOf(CAROL) == 1_000_000e18, "third takes 1M");
        require(prize.winnerCount() == 3, "three winners");

        RefractionPrizeV1.Winner[] memory board = prize.leaderboard();
        require(board[0].solver == ALICE && board[1].solver == BOB, "board is ordered");
        require(board[0].award == 3_000_000e18, "board records the award");
        require(prize.nextAward() == 0, "nothing left to win");
    }

    /// The reason the contract is commit-reveal at all. A watcher who sees a
    /// reveal in the mempool learns the answer, but the place is already taken
    /// by a commitment it cannot forge.
    function test_a_watcher_who_learns_the_answer_cannot_take_the_place() public {
        VM.prank(ALICE);
        prize.commit(_commitment(ANSWER, ALICE, bytes32("a")));
        VM.roll(block.number + 1);

        // The bot has seen Alice's answer and races her reveal with its own.
        VM.prank(BOT);
        (bool blind,) =
            address(prize).call(abi.encodeCall(RefractionPrizeV1.reveal, (ANSWER, bytes32("a"))));
        require(!blind, "a reveal without a commitment is refused");

        // Copying the commitment bytes does not help: they are bound to Alice.
        VM.prank(BOT);
        prize.commit(_commitment(ANSWER, ALICE, bytes32("a")));
        VM.roll(block.number + 1);
        require(_revealReverts(BOT, ANSWER, bytes32("a")), "a stolen commitment cannot be opened");

        VM.prank(ALICE);
        prize.reveal(ANSWER, bytes32("a"));
        require(prism.balanceOf(ALICE) == 3_000_000e18, "the solver still takes first");
    }

    /// A commitment is proof of the answer, so nobody can reserve a place before
    /// solving and open it later.
    function test_a_place_cannot_be_squatted_before_solving() public {
        VM.prank(BOT);
        prize.commit(keccak256("a guess"));
        VM.roll(block.number + 1);
        require(_revealReverts(BOT, ANSWER, bytes32("a guess")), "a blind commitment is worthless");
        require(prize.winnerCount() == 0, "nobody has won");
    }

    function test_a_commitment_cannot_be_opened_in_the_block_it_was_made() public {
        VM.prank(ALICE);
        prize.commit(_commitment(ANSWER, ALICE, bytes32("a")));
        require(_revealReverts(ALICE, ANSWER, bytes32("a")), "same block is refused");
        VM.roll(block.number + 1);
        VM.prank(ALICE);
        prize.reveal(ANSWER, bytes32("a"));
        require(prize.winnerCount() == 1, "the next block is fine");
    }

    function test_a_wrong_answer_wins_nothing() public {
        VM.prank(ALICE);
        prize.commit(_commitment("not the answer", ALICE, bytes32("a")));
        VM.roll(block.number + 1);
        require(_revealReverts(ALICE, "not the answer", bytes32("a")), "wrong answer refused");
        require(prism.balanceOf(ALICE) == 0, "and pays nothing");
    }

    function test_one_solver_cannot_take_two_places() public {
        _solve(ALICE, bytes32("a"));
        require(_revealReverts(ALICE, ANSWER, bytes32("a")), "a second reveal is refused");
        require(prism.balanceOf(ALICE) == 3_000_000e18, "still only the first award");
    }

    function test_a_fourth_solver_arrives_too_late() public {
        _solve(ALICE, bytes32("a"));
        _solve(BOB, bytes32("b"));
        _solve(CAROL, bytes32("c"));
        VM.prank(DAN);
        (bool ok,) = address(prize)
            .call(
                abi.encodeCall(RefractionPrizeV1.commit, (_commitment(ANSWER, DAN, bytes32("d"))))
            );
        require(!ok, "committing after the last place is refused");
        require(prism.balanceOf(DAN) == 0, "and pays nothing");
    }

    function test_unclaimed_prizes_go_back_only_after_the_deadline() public {
        _solve(ALICE, bytes32("a"));

        VM.prank(TREASURY);
        (bool early,) = address(prize).call(abi.encodeCall(RefractionPrizeV1.reclaim, ()));
        require(!early, "not before the deadline");

        VM.warp(DEADLINE + 1);
        VM.prank(BOT);
        (bool wrongCaller,) = address(prize).call(abi.encodeCall(RefractionPrizeV1.reclaim, ()));
        require(!wrongCaller, "only the treasury");

        VM.prank(TREASURY);
        prize.reclaim();
        require(prism.balanceOf(TREASURY) == 3_000_000e18, "the two unclaimed awards return");
        require(prism.balanceOf(ALICE) == 3_000_000e18, "the winner keeps theirs");
    }

    function test_commitments_are_a_public_progress_signal() public {
        require(prize.commitments() == 0, "nobody yet");
        VM.prank(ALICE);
        prize.commit(_commitment(ANSWER, ALICE, bytes32("a")));
        VM.prank(BOB);
        prize.commit(_commitment(ANSWER, BOB, bytes32("b")));
        require(prize.commitments() == 2, "two people hold the answer");
        require(prize.winnerCount() == 0, "and neither has claimed yet");
    }
}

interface Vm {
    function warp(uint256 newTimestamp) external;
    function roll(uint256 newHeight) external;
    function prank(address msgSender) external;
}
