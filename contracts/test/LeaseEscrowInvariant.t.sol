// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "../src/interfaces/IERC20.sol";
import { LeaseEscrowV1 } from "../src/LeaseEscrowV1.sol";
import { NodeRegistryV1 } from "../src/NodeRegistryV1.sol";

contract InvariantUsd is IERC20 {
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

contract LeaseLifecycleHandler {
    VmInvariant private constant VM =
        VmInvariant(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant ATTESTOR_KEY = 0xA11CE;

    InvariantUsd public usd;
    LeaseEscrowV1 public escrow;
    bytes32 public nodeId;

    function configure(InvariantUsd usd_, LeaseEscrowV1 escrow_, bytes32 nodeId_) external {
        if (address(escrow) != address(0)) return;
        usd = usd_;
        escrow = escrow_;
        nodeId = nodeId_;
        usd_.approve(address(escrow_), type(uint256).max);
    }

    function create(uint32 seed) external {
        uint32 duration = uint32(1 + uint256(seed) % escrow.MAX_DURATION());
        bytes32 clientReference = keccak256(abi.encode(seed, escrow.leaseCount() + 1));
        try escrow.createLease(nodeId, duration, clientReference) { } catch { }
    }

    function start() external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        if (lease.status != LeaseEscrowV1.LeaseStatus.Funded) return;
        try escrow.startAccess(leaseId) { } catch { }
    }

    function close(uint32 seed) external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        if (lease.status != LeaseEscrowV1.LeaseStatus.Active || lease.accessEndedAt != 0) return;
        VM.warp(block.timestamp + uint256(seed) % (uint256(lease.duration) + 1));
        try escrow.closeAccess(leaseId) { } catch { }
    }

    function propose(uint64 seed) external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        if (lease.status != LeaseEscrowV1.LeaseStatus.Active || lease.accessEndedAt == 0) return;
        uint64 observed = lease.accessEndedAt - lease.accessStartedAt;
        uint64 maximum = observed > lease.duration ? lease.duration : observed;
        uint64 usage = uint64(uint256(seed) % (uint256(maximum) + 1));
        bytes32 receiptHash = keccak256(abi.encode(leaseId, usage, lease.nonce));
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                escrow.domainSeparator(),
                keccak256(
                    abi.encode(
                        escrow.SETTLEMENT_TYPEHASH(),
                        leaseId,
                        usage,
                        receiptHash,
                        lease.nonce,
                        deadline
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(ATTESTOR_KEY, digest);
        try escrow.proposeSettlement(
            leaseId, usage, receiptHash, deadline, abi.encodePacked(r, s, v)
        ) { }
            catch { }
    }

    function dispute() external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        try escrow.dispute(leaseId) { } catch { }
    }

    function finalize() external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        if (lease.status != LeaseEscrowV1.LeaseStatus.SettlementProposed) return;
        VM.warp(lease.proposedAt + escrow.DISPUTE_WINDOW());
        try escrow.finalize(leaseId) { } catch { }
    }

    function resolve(uint64 seed) external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        if (lease.status != LeaseEscrowV1.LeaseStatus.Disputed) return;
        uint64 observed = lease.accessEndedAt - lease.accessStartedAt;
        uint64 maximum = observed > lease.duration ? lease.duration : observed;
        uint64 usage = uint64(uint256(seed) % (uint256(maximum) + 1));
        try escrow.resolveDispute(
            leaseId, usage, keccak256(abi.encode("resolved", leaseId, usage))
        ) { }
            catch { }
    }

    function cancel() external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        try escrow.cancelUnprovisioned(leaseId, keccak256("cancelled")) { } catch { }
    }

    function expire() external {
        uint256 leaseId = escrow.leaseCount();
        if (leaseId == 0) return;
        LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
        if (lease.status != LeaseEscrowV1.LeaseStatus.Funded) return;
        VM.warp(lease.createdAt + escrow.PROVISION_TIMEOUT() + 1);
        try escrow.expireProvision(leaseId, keccak256("expired")) { } catch { }
    }
}

contract LeaseEscrowInvariantTest {
    VmInvariant private constant VM =
        VmInvariant(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant ATTESTOR_KEY = 0xA11CE;
    uint256 private constant PROVIDER_KEY = 0xBEEF;
    bytes32 private constant NODE_ID = keccak256("invariant-device");
    uint256 private constant INITIAL_SUPPLY = 2_000_000_000;

    InvariantUsd private usd;
    NodeRegistryV1 private registry;
    LeaseEscrowV1 private escrow;
    LeaseLifecycleHandler private handler;
    address private provider;
    address private treasury;

    function setUp() public {
        provider = VM.addr(PROVIDER_KEY);
        treasury = address(0xCAFE);
        usd = new InvariantUsd();
        registry = new NodeRegistryV1(usd, treasury);
        handler = new LeaseLifecycleHandler();
        escrow = new LeaseEscrowV1(
            usd,
            registry,
            address(this),
            address(handler),
            VM.addr(ATTESTOR_KEY),
            treasury,
            address(this),
            address(handler)
        );
        handler.configure(usd, escrow, NODE_ID);
        registry.setEscrow(address(escrow));
        escrow.unpause();

        usd.mint(address(handler), 1_000_000_000);
        usd.mint(provider, 1_000_000_000);
        VM.prank(provider);
        usd.approve(address(registry), type(uint256).max);
        _registerNode();
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function invariantEscrowBalanceCoversEveryOpenLease() public view {
        uint256 unresolved;
        uint256 active;
        for (uint256 leaseId = 1; leaseId <= escrow.leaseCount(); leaseId++) {
            LeaseEscrowV1.Lease memory lease = escrow.getLease(leaseId);
            if (
                lease.status == LeaseEscrowV1.LeaseStatus.Funded
                    || lease.status == LeaseEscrowV1.LeaseStatus.Active
                    || lease.status == LeaseEscrowV1.LeaseStatus.SettlementProposed
                    || lease.status == LeaseEscrowV1.LeaseStatus.Disputed
            ) {
                unresolved += lease.deposit;
                active += 1;
            }
        }
        require(usd.balanceOf(address(escrow)) == unresolved, "escrow is insolvent");
        require(escrow.activeLeaseCount() == active, "active lease count diverged");
        require(active <= 1, "one node backed multiple leases");
    }

    function invariantNodeReservationMatchesActiveLease() public view {
        uint64 activeLeaseId = registry.getNode(NODE_ID).activeLeaseId;
        if (escrow.activeLeaseCount() == 0) {
            require(activeLeaseId == 0, "terminal lease retained node");
            return;
        }
        require(activeLeaseId != 0, "active lease lost node reservation");
        LeaseEscrowV1.Lease memory lease = escrow.getLease(activeLeaseId);
        require(lease.nodeId == NODE_ID, "node reserved by another lease");
    }

    function invariantTokenConservation() public view {
        uint256 total = usd.balanceOf(address(handler)) + usd.balanceOf(provider)
            + usd.balanceOf(treasury) + usd.balanceOf(address(registry))
            + usd.balanceOf(address(escrow));
        require(total == INITIAL_SUPPLY, "token accounting diverged");
    }

    function _registerNode() private {
        bytes32 metadataHash = keccak256("invariant-offer");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = registry.enrollmentDigest(
            NODE_ID,
            NODE_ID,
            provider,
            provider,
            1_000,
            metadataHash,
            registry.enrollmentNonces(provider),
            deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(PROVIDER_KEY, digest);
        VM.prank(provider);
        registry.register(
            NODE_ID, NODE_ID, provider, 1_000, metadataHash, deadline, abi.encodePacked(r, s, v)
        );
    }
}

interface VmInvariant {
    function addr(uint256 privateKey) external returns (address keyAddr);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address msgSender) external;
    function warp(uint256 newTimestamp) external;
}
