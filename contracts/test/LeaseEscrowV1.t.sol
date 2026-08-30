// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "../src/interfaces/IERC20.sol";
import { AdminTimelockV1 } from "../src/AdminTimelockV1.sol";
import { NodeRegistryV1 } from "../src/NodeRegistryV1.sol";
import { LeaseEscrowV1 } from "../src/LeaseEscrowV1.sol";

contract MockUsd is IERC20 {
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

contract TimelockTarget {
    uint256 public value;

    function setValue(uint256 value_) external {
        value = value_;
    }
}

contract LeaseEscrowV1Test {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    MockUsd private usd;
    NodeRegistryV1 private registry;
    LeaseEscrowV1 private escrow;
    bytes32 private constant NODE_ID = keccak256("device");
    uint256 private constant ATTESTOR_KEY = 0xA11CE;
    uint256 private constant PROVIDER_KEY = 0xBEEF;
    address private immutable PROVIDER = VM.addr(PROVIDER_KEY);
    address private constant TREASURY = address(0xCAFE);

    function setUp() public {
        usd = new MockUsd();
        registry = new NodeRegistryV1(usd, address(this), 4_505, 1_000_000, 100_000_000);
        escrow = new LeaseEscrowV1(
            usd,
            registry,
            address(this),
            address(this),
            VM.addr(ATTESTOR_KEY),
            TREASURY,
            address(this),
            address(this)
        );
        registry.setEscrow(address(escrow));
        escrow.unpause();
        usd.mint(address(this), 1_000_000_000);
        usd.mint(PROVIDER, 1_000_000_000);
        usd.approve(address(registry), type(uint256).max);
        usd.approve(address(escrow), type(uint256).max);
        VM.prank(PROVIDER);
        usd.approve(address(registry), type(uint256).max);
        _registerNode();
    }

    function testRequiredBondScalesWithRateInsideTheBand() public view {
        // 4_505 per unit of rate, floor 1_000_000, ceiling 100_000_000.
        require(registry.requiredBond(1_000) == 4_505_000, "bond scales with the advertised rate");
        require(registry.requiredBond(2_000) == 9_010_000, "twice the rate stakes twice as much");
        require(registry.requiredBond(1) == 1_000_000, "the floor catches rates below it");
        require(
            registry.requiredBond(type(uint128).max) == 100_000_000,
            "the ceiling caps an extreme rate rather than reverting"
        );
    }

    function testAdminCloseOnlyEverRefundsTheRenter() public {
        uint256 balanceBefore = usd.balanceOf(address(this));
        uint256 treasuryBefore = usd.balanceOf(TREASURY);
        uint256 leaseId = _createLease(3_600);
        VM.warp(block.timestamp + 1);
        escrow.startAccess(leaseId);

        escrow.adminClose(leaseId, keccak256("stuck lease"));

        require(usd.balanceOf(address(this)) == balanceBefore, "renter was not made whole");
        require(usd.balanceOf(TREASURY) == treasuryBefore, "admin close paid the treasury");
        require(
            escrow.getLease(leaseId).status == LeaseEscrowV1.LeaseStatus.Refunded,
            "lease was not refunded"
        );
        require(escrow.activeLeaseCount() == 0, "lease was not released");
        require(registry.getNode(NODE_ID).activeLeaseId == 0, "node was not released");
    }

    function testAdminCloseCannotReopenASettledLease() public {
        uint256 leaseId = _createLease(3_600);
        VM.warp(block.timestamp + 1);
        escrow.startAccess(leaseId);
        VM.warp(block.timestamp + 600);
        escrow.closeAccess(leaseId);
        _propose(leaseId, 600, keccak256("receipt"));
        VM.warp(block.timestamp + 24 hours);
        escrow.finalize(leaseId);

        (bool success,) = address(escrow)
            .call(abi.encodeCall(escrow.adminClose, (leaseId, keccak256("too late"))));
        require(!success, "admin close reopened a finalized lease");
    }

    function testAdminCloseRejectsCallersOtherThanTheEmergencyAdmin() public {
        uint256 leaseId = _createLease(3_600);
        VM.prank(PROVIDER);
        (bool success,) = address(escrow)
            .call(abi.encodeCall(escrow.adminClose, (leaseId, keccak256("not admin"))));
        require(!success, "a non-admin closed a lease");
    }

    function testEscrowReservesNodeAndStartsOnlyThroughGateway() public {
        uint256 leaseId = _createLease(3_600);
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        require(lease.deposit == 10_800_000, "incorrect escrow");
        require(lease.duration == 3_600, "incorrect duration");
        require(registry.getNode(NODE_ID).activeLeaseId == leaseId, "node was not reserved");
        escrow.startAccess(leaseId);
        require(
            escrow.getLease(leaseId).status == LeaseEscrowV1.LeaseStatus.Active,
            "access did not start"
        );
    }

    function testClientReferenceCannotBeReused() public {
        bytes32 clientReference = keccak256("quote-reference");
        uint256 leaseId = escrow.createLease(NODE_ID, 60, clientReference);
        escrow.cancelUnprovisioned(leaseId, keccak256("cancelled"));
        (bool reused,) =
            address(escrow).call(abi.encodeCall(escrow.createLease, (NODE_ID, 60, clientReference)));
        require(!reused, "client reference was reused");
    }

    function testEscrowStartsPaused() public {
        LeaseEscrowV1 pausedEscrow = new LeaseEscrowV1(
            usd,
            registry,
            address(this),
            address(this),
            VM.addr(ATTESTOR_KEY),
            address(this),
            address(this),
            address(this)
        );
        require(pausedEscrow.paused(), "deployment must start paused");
    }

    function testEmergencyAdminCanPauseImmediately() public {
        escrow.pause();
        (bool success,) = address(escrow)
            .call(abi.encodeCall(escrow.createLease, (NODE_ID, 60, keccak256("paused"))));
        require(!success, "emergency pause did not stop new escrow");
    }

    function testConfigurationTimelockDefersExecution() public {
        AdminTimelockV1 timelock = new AdminTimelockV1(address(this));
        TimelockTarget target = new TimelockTarget();
        bytes memory data = abi.encodeCall(target.setValue, (42));
        bytes32 salt = keccak256("set value");
        timelock.schedule(address(target), 0, data, salt);

        (bool early,) = address(timelock)
            .call(abi.encodeCall(timelock.execute, (address(target), 0, data, salt)));
        require(!early, "timelock executed before delay");
        VM.warp(block.timestamp + 48 hours);
        timelock.execute(address(target), 0, data, salt);
        require(target.value() == 42, "timelock execution failed");
    }

    function testEscrowCapRejectsLargeLease() public {
        (bool success,) = address(escrow)
            .call(abi.encodeCall(escrow.createLease, (NODE_ID, 21_600, keccak256("large"))));
        require(!success, "lease exceeded the cap");
    }

    function testFinalizationConservesEscrowAndPaysTheSplit() public {
        uint256 leaseId = _createLease(3_600);
        VM.warp(block.timestamp + 1);
        escrow.startAccess(leaseId);
        VM.warp(block.timestamp + 600);
        escrow.closeAccess(leaseId);

        bytes32 receiptHash = keccak256("receipt");
        _propose(leaseId, 600, receiptHash);
        VM.warp(block.timestamp + 24 hours);
        escrow.finalize(leaseId);

        uint256 charge = 1_800_000;
        require(
            usd.balanceOf(PROVIDER) == 1_000_000_000 - registry.requiredBond(3_000) + 1_620_000,
            "provider share is wrong"
        );
        require(usd.balanceOf(TREASURY) == 180_000, "protocol fee is wrong");
        require(usd.balanceOf(address(this)) == 1_000_000_000 - charge, "renter refund is wrong");
        require(escrow.activeLeaseCount() == 0, "lease was not released");
        require(registry.getNode(NODE_ID).activeLeaseId == 0, "node was not released");
    }

    function testDisputedSettlementCannotFinalizeWithoutAdminResolution() public {
        uint256 leaseId = _createLease(60);
        VM.warp(block.timestamp + 1);
        escrow.startAccess(leaseId);
        VM.warp(block.timestamp + 60);
        escrow.closeAccess(leaseId);
        _propose(leaseId, 60, keccak256("disputed receipt"));
        escrow.dispute(leaseId);
        VM.warp(block.timestamp + 24 hours);
        (bool finalized,) = address(escrow).call(abi.encodeCall(escrow.finalize, (leaseId)));
        require(!finalized, "disputed settlement finalized");
    }

    function testNodeRegistrationRejectsAnInvalidDeviceBinding() public {
        bytes32 nodeId = keccak256("another-device");
        bytes32 metadataHash = keccak256("another-offer");
        uint256 deadline = block.timestamp + 1 hours;
        VM.prank(PROVIDER);
        (bool registered,) = address(registry)
            .call(
                abi.encodeCall(
                    registry.register,
                    (nodeId, nodeId, PROVIDER, 1_000, metadataHash, deadline, bytes(""))
                )
            );
        require(!registered, "registration accepted an invalid device binding");
    }

    function testNodeRegistrationAcceptsExtremeRateAtTheCeiling() public {
        bytes32 nodeId = keccak256("unbounded-rate-device");
        bytes32 metadataHash = keccak256("unbounded-rate-offer");
        uint128 rate = type(uint128).max;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = registry.enrollmentDigest(
            nodeId,
            nodeId,
            PROVIDER,
            PROVIDER,
            rate,
            metadataHash,
            registry.enrollmentNonces(PROVIDER),
            deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(PROVIDER_KEY, digest);
        VM.prank(PROVIDER);
        (bool registered,) = address(registry)
            .call(
                abi.encodeCall(
                    registry.register,
                    (
                        nodeId,
                        nodeId,
                        PROVIDER,
                        rate,
                        metadataHash,
                        deadline,
                        abi.encodePacked(r, s, v)
                    )
                )
            );
        require(registered, "a bounded bond should accept any rate");
        require(
            registry.getNode(nodeId).bond == 100_000_000,
            "an extreme rate stakes the ceiling, not an unpayable figure"
        );
    }

    function testRetiredNodeCanWithdrawItsEntireBond() public {
        uint128 bonded = registry.getNode(NODE_ID).bond;
        uint256 before = usd.balanceOf(PROVIDER);

        VM.startPrank(PROVIDER);
        registry.retire(NODE_ID);
        registry.withdrawBond(NODE_ID, uint128(bonded));
        VM.stopPrank();

        require(registry.getNode(NODE_ID).bond == 0, "retired bond remained locked");
        require(usd.balanceOf(PROVIDER) == before + bonded, "retired bond was not returned");
    }

    function testActiveNodeCannotWithdrawBelowRequiredBond() public {
        VM.prank(PROVIDER);
        (bool withdrawn,) =
            address(registry).call(abi.encodeCall(registry.withdrawBond, (NODE_ID, uint128(1))));
        require(!withdrawn, "active node withdrew required collateral");
    }

    function testGatewayCannotExtendObservedRuntimeByClosingTwice() public {
        uint256 leaseId = _createLease(600);
        VM.warp(block.timestamp + 1);
        escrow.startAccess(leaseId);
        VM.warp(block.timestamp + 60);
        escrow.closeAccess(leaseId);
        VM.warp(block.timestamp + 60);

        (bool closed,) = address(escrow).call(abi.encodeCall(escrow.closeAccess, (leaseId)));
        require(!closed, "gateway changed an already closed access window");
    }

    function testFuzzSettlementConservesDeposit(uint32 rawDuration, uint32 rawUsage) public {
        uint32 duration = uint32(1 + uint256(rawDuration) % 3_600);
        uint64 usage = uint64(uint256(rawUsage) % (uint256(duration) + 1));
        uint256 renterBefore = usd.balanceOf(address(this));
        uint256 providerBefore = usd.balanceOf(PROVIDER);
        uint256 treasuryBefore = usd.balanceOf(TREASURY);
        uint256 leaseId = _createLease(duration);

        VM.warp(block.timestamp + 1);
        escrow.startAccess(leaseId);
        VM.warp(block.timestamp + usage);
        escrow.closeAccess(leaseId);
        _propose(leaseId, usage, keccak256(abi.encode(duration, usage)));
        VM.warp(block.timestamp + 24 hours);
        escrow.finalize(leaseId);

        uint256 charged = uint256(usage) * 3_000;
        uint256 fee = charged * escrow.PLATFORM_FEE_BPS() / escrow.BPS_DENOMINATOR();
        require(usd.balanceOf(address(this)) == renterBefore - charged, "renter total changed");
        require(usd.balanceOf(PROVIDER) == providerBefore + charged - fee, "provider total changed");
        require(usd.balanceOf(TREASURY) == treasuryBefore + fee, "treasury total changed");
        require(usd.balanceOf(address(escrow)) == 0, "escrow retained a terminal balance");
    }

    function _propose(uint256 leaseId, uint64 usageSeconds, bytes32 receiptHash) private {
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                escrow.domainSeparator(),
                keccak256(
                    abi.encode(
                        escrow.SETTLEMENT_TYPEHASH(),
                        leaseId,
                        usageSeconds,
                        receiptHash,
                        lease.nonce,
                        deadline
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(ATTESTOR_KEY, digest);
        escrow.proposeSettlement(
            leaseId, usageSeconds, receiptHash, deadline, abi.encodePacked(r, s, v)
        );
    }

    function _createLease(uint32 duration) private returns (uint256) {
        return escrow.createLease(
            NODE_ID, duration, keccak256(abi.encode("quote", escrow.leaseCount() + 1))
        );
    }

    /// Capacity is staked in one asset and compute is billed in another. The
    /// bond amount is also a deployment parameter now, because the old constant
    /// of 1_000_000 means one unit of a six decimal stablecoin and a millionth
    /// of a millionth of an eighteen decimal token.
    function test_bondTokenIsSeparateFromThePaymentToken() public {
        MockUsd bondToken = new MockUsd();
        // 50,000 whole tokens at the 222 unit rate the network charges today.
        uint256 perRateUnit = 225_225_225_225_225_225_225;
        uint256 stake = perRateUnit * 222;
        NodeRegistryV1 staked =
            new NodeRegistryV1(bondToken, address(this), perRateUnit, 1e18, 1_000_000e18);

        require(address(staked.bondToken()) == address(bondToken), "bond token is the staked asset");
        require(staked.requiredBond(222) == stake, "bond scales with the advertised rate");
        require(staked.requiredBond(444) == stake * 2, "twice the rate stakes twice as much");
        require(staked.requiredBond(0) == 1e18, "the floor applies when nothing scales");
        require(staked.requiredBond(type(uint128).max) == 1_000_000e18, "the ceiling caps the bond");

        bondToken.mint(PROVIDER, perRateUnit * 3_000);
        VM.prank(PROVIDER);
        bondToken.approve(address(staked), type(uint256).max);

        uint256 paymentBefore = usd.balanceOf(PROVIDER);
        bytes32 nodeId = keccak256("staked-device");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = staked.enrollmentDigest(
            nodeId,
            nodeId,
            PROVIDER,
            PROVIDER,
            3_000,
            keccak256("offer"),
            staked.enrollmentNonces(PROVIDER),
            deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(PROVIDER_KEY, digest);
        VM.prank(PROVIDER);
        staked.register(
            nodeId, nodeId, PROVIDER, 3_000, keccak256("offer"), deadline, abi.encodePacked(r, s, v)
        );

        // The stake left the bond token and the payment balance is untouched.
        uint256 required = staked.requiredBond(3_000);
        require(bondToken.balanceOf(address(staked)) == required, "registry holds the stake");
        require(
            bondToken.balanceOf(PROVIDER) == perRateUnit * 3_000 - required,
            "stake was pulled from the bond token"
        );
        require(usd.balanceOf(PROVIDER) == paymentBefore, "payment balance was untouched");
    }

    function _registerNode() private {
        bytes32 metadataHash = keccak256("offer");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = registry.enrollmentDigest(
            NODE_ID,
            NODE_ID,
            PROVIDER,
            PROVIDER,
            3_000,
            metadataHash,
            registry.enrollmentNonces(PROVIDER),
            deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(PROVIDER_KEY, digest);
        VM.prank(PROVIDER);
        registry.register(
            NODE_ID, NODE_ID, PROVIDER, 3_000, metadataHash, deadline, abi.encodePacked(r, s, v)
        );
    }
}

interface Vm {
    function addr(uint256 privateKey) external returns (address keyAddr);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
    function prank(address msgSender) external;
    function startPrank(address msgSender) external;
    function stopPrank() external;
}
