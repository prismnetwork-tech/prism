// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "../src/interfaces/IERC20.sol";
import { PrismStakeV1 } from "../src/PrismStakeV1.sol";

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

contract PrismStakeV1Test {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);

    MockPrism private prism;
    PrismStakeV1 private staking;

    function setUp() public {
        prism = new MockPrism();
        staking = new PrismStakeV1(address(prism));
        prism.mint(ALICE, 1_000e18);
        prism.mint(BOB, 1_000e18);
        VM.prank(ALICE);
        prism.approve(address(staking), type(uint256).max);
        VM.prank(BOB);
        prism.approve(address(staking), type(uint256).max);
    }

    function _stake(address who, uint256 amount) private {
        VM.prank(who);
        staking.stake(amount);
    }

    function _stakeReverts(address who, uint256 amount) private returns (bool) {
        VM.prank(who);
        (bool ok,) = address(staking).call(abi.encodeCall(PrismStakeV1.stake, (amount)));
        return !ok;
    }

    function _unstakeReverts(address who, uint256 amount) private returns (bool) {
        VM.prank(who);
        (bool ok,) = address(staking).call(abi.encodeCall(PrismStakeV1.unstake, (amount)));
        return !ok;
    }

    function _withdrawReverts(address who) private returns (bool) {
        VM.prank(who);
        (bool ok,) = address(staking).call(abi.encodeCall(PrismStakeV1.withdraw, ()));
        return !ok;
    }

    function test_stake_counts_only_once_mature() public {
        _stake(ALICE, 100e18);

        require(prism.balanceOf(address(staking)) == 100e18, "tokens did not move");
        require(staking.totalStaked() == 100e18, "totalStaked wrong");
        require(staking.eligibleStakeOf(ALICE) == 0, "counted before maturity");

        VM.warp(block.timestamp + staking.MATURITY());
        require(staking.eligibleStakeOf(ALICE) == 100e18, "did not count after maturity");
    }

    // The whole point of maturity: a balance borrowed for one block must not be
    // able to price a lease.
    function test_stake_and_leave_in_one_block_earns_nothing() public {
        _stake(ALICE, 500e18);
        require(staking.eligibleStakeOf(ALICE) == 0, "flash stake counted");

        VM.prank(ALICE);
        staking.unstake(500e18);
        require(staking.eligibleStakeOf(ALICE) == 0, "flash stake counted after leaving");
    }

    function test_topping_up_restarts_maturity() public {
        _stake(ALICE, 100e18);
        VM.warp(block.timestamp + staking.MATURITY());
        require(staking.eligibleStakeOf(ALICE) == 100e18, "not mature");

        _stake(ALICE, 1e18);
        require(staking.eligibleStakeOf(ALICE) == 0, "top-up backdated maturity");

        VM.warp(block.timestamp + staking.MATURITY());
        require(staking.eligibleStakeOf(ALICE) == 101e18, "top-up never matured");
    }

    // Leaving stops the discount immediately, before the tokens come back.
    function test_unstake_stops_counting_before_cooldown_ends() public {
        _stake(ALICE, 100e18);
        VM.warp(block.timestamp + staking.MATURITY());

        VM.prank(ALICE);
        staking.unstake(40e18);

        require(staking.eligibleStakeOf(ALICE) == 60e18, "unbonding still counted");
        require(staking.totalStaked() == 60e18, "totalStaked kept the unbonding amount");
    }

    function test_withdraw_waits_for_the_cooldown() public {
        _stake(ALICE, 100e18);
        VM.prank(ALICE);
        staking.unstake(100e18);

        require(_withdrawReverts(ALICE), "withdrew during cooldown");

        VM.warp(block.timestamp + staking.COOLDOWN());
        VM.prank(ALICE);
        staking.withdraw();

        require(prism.balanceOf(ALICE) == 1_000e18, "stake not returned");
        require(prism.balanceOf(address(staking)) == 0, "contract kept tokens");
    }

    function test_rejects_impossible_amounts() public {
        require(_stakeReverts(ALICE, 0), "staked zero");
        _stake(ALICE, 10e18);
        require(_unstakeReverts(ALICE, 0), "unstaked zero");
        require(_unstakeReverts(ALICE, 11e18), "unstaked more than staked");
        require(_withdrawReverts(ALICE), "withdrew with nothing unbonding");
    }

    // One staker must never reach another's position, and there is no
    // privileged path either: the contract has no owner.
    function test_positions_are_isolated() public {
        _stake(ALICE, 100e18);
        _stake(BOB, 5e18);
        VM.warp(block.timestamp + staking.MATURITY());

        require(staking.eligibleStakeOf(ALICE) == 100e18, "alice not counted");
        require(staking.eligibleStakeOf(BOB) == 5e18, "bob not counted");
        require(_unstakeReverts(BOB, 100e18), "bob reached alice's stake");

        VM.prank(BOB);
        staking.unstake(5e18);
        VM.warp(block.timestamp + staking.COOLDOWN());
        VM.prank(BOB);
        staking.withdraw();

        require(staking.eligibleStakeOf(ALICE) == 100e18, "alice's stake moved");
        require(prism.balanceOf(address(staking)) == 100e18, "alice's tokens left");
    }

    function test_rejects_a_zero_token() public {
        (bool ok,) = address(this).call(abi.encodeCall(PrismStakeV1Test.deployWithZeroToken, ()));
        require(!ok, "deployed against the zero address");
    }

    function deployWithZeroToken() external {
        new PrismStakeV1(address(0));
    }

    /// Whatever the sequence, the contract holds at least what it owes and can
    /// never price a discount off more than is actually staked.
    function testFuzz_always_covers_its_obligations(
        uint96 first,
        uint96 second,
        uint96 leave,
        uint32 elapsed
    ) public {
        uint256 a = (uint256(first) % 400e18) + 1;
        uint256 b = (uint256(second) % 400e18) + 1;
        uint256 out = uint256(leave) % (a + b + 1);

        _stake(ALICE, a);
        VM.warp(block.timestamp + (uint256(elapsed) % 30 days));
        _stake(ALICE, b);

        if (out > 0) {
            VM.prank(ALICE);
            staking.unstake(out);
        }

        (uint256 staked, uint256 unbonding,,) = staking.positionOf(ALICE);
        require(staked + unbonding == a + b, "tokens vanished");
        require(prism.balanceOf(address(staking)) >= staked + unbonding, "cannot repay everyone");
        require(staking.totalStaked() == staked, "totalStaked drifted from the position");
        require(staking.eligibleStakeOf(ALICE) <= staked, "discount counted more than staked");
    }
}

interface Vm {
    function warp(uint256 newTimestamp) external;
    function prank(address msgSender) external;
}
