// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "./interfaces/IERC20.sol";
import { TokenTransfers } from "./lib/TokenTransfers.sol";
import { NodeRegistryV1 } from "./NodeRegistryV1.sol";

contract LeaseEscrowV1 {
    using TokenTransfers for IERC20;

    uint256 private constant SECP256K1N_DIV_2 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 public constant MAX_ESCROW = 50_000_000;
    uint32 public constant MAX_DURATION = 6 hours;
    uint32 public constant PROVISION_TIMEOUT = 10 minutes;
    uint32 public constant DISPUTE_WINDOW = 24 hours;
    uint16 public constant PLATFORM_FEE_BPS = 1_000;
    uint16 public constant BPS_DENOMINATOR = 10_000;
    uint16 public constant MAX_ACTIVE_LEASES = 25;

    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant SETTLEMENT_TYPEHASH = keccak256(
        "Settlement(uint256 leaseId,uint64 usageSeconds,bytes32 receiptHash,uint256 nonce,uint256 deadline)"
    );

    enum LeaseStatus {
        None,
        Funded,
        Active,
        SettlementProposed,
        Disputed,
        Finalized,
        Refunded
    }

    struct Lease {
        address renter;
        bytes32 nodeId;
        bytes32 clientReference;
        uint128 ratePerSecond;
        uint128 deposit;
        uint32 duration;
        uint64 createdAt;
        uint64 accessStartedAt;
        uint64 accessEndedAt;
        uint64 proposedUsageSeconds;
        uint64 proposedAt;
        uint128 nonce;
        bytes32 receiptHash;
        LeaseStatus status;
    }

    error ActiveLeaseLimit();
    error AlreadyPaused();
    error Expired();
    error InvalidAddress();
    error InvalidDuration();
    error InvalidLease();
    error InvalidSignature();
    error InvalidState();
    error LeaseNotReady();
    error LimitExceeded();
    error NotAdmin();
    error NotGateway();
    error NotRenter();
    error NotPaused();
    error SettlementTooEarly();
    error Unauthorized();
    error UsageExceeded();
    error Reentrancy();
    error ReferenceUsed();

    event LeaseFunded(
        uint256 indexed leaseId,
        bytes32 indexed nodeId,
        address indexed renter,
        uint256 deposit,
        uint32 duration,
        bytes32 clientReference
    );
    event LeaseAccessStarted(uint256 indexed leaseId, uint64 startedAt);
    event LeaseAccessClosed(uint256 indexed leaseId, uint64 endedAt);
    event SettlementProposed(
        uint256 indexed leaseId, uint64 usageSeconds, bytes32 receiptHash, uint256 deadline
    );
    event LeaseDisputed(uint256 indexed leaseId, address indexed renter);
    event LeaseFinalized(
        uint256 indexed leaseId,
        uint256 charged,
        uint256 fee,
        uint256 providerPaid,
        uint256 refunded,
        bytes32 receiptHash
    );
    event LeaseRefunded(uint256 indexed leaseId, uint256 refunded, bytes32 reasonHash);
    event AttestorSet(address indexed attestor);
    event GatewaySet(address indexed gateway);
    event Paused(address indexed admin);
    event Unpaused(address indexed admin);

    IERC20 public immutable usd;
    NodeRegistryV1 public immutable nodeRegistry;
    address public immutable admin;
    address public gateway;
    address public attestor;
    address public immutable treasury;
    address public immutable emergencyAdmin;
    address public immutable disputeResolver;
    bool public paused;
    uint256 public leaseCount;
    uint16 public activeLeaseCount;
    uint256 private unlocked = 1;
    mapping(uint256 leaseId => Lease lease) private leases;
    mapping(bytes32 clientReference => bool used) public usedClientReferences;

    constructor(
        IERC20 usd_,
        NodeRegistryV1 nodeRegistry_,
        address admin_,
        address gateway_,
        address attestor_,
        address treasury_,
        address emergencyAdmin_,
        address disputeResolver_
    ) {
        if (
            address(usd_) == address(0) || address(nodeRegistry_) == address(0)
                || admin_ == address(0) || gateway_ == address(0) || attestor_ == address(0)
                || treasury_ == address(0) || emergencyAdmin_ == address(0)
                || disputeResolver_ == address(0)
        ) revert InvalidAddress();
        usd = usd_;
        nodeRegistry = nodeRegistry_;
        admin = admin_;
        gateway = gateway_;
        attestor = attestor_;
        treasury = treasury_;
        emergencyAdmin = emergencyAdmin_;
        disputeResolver = disputeResolver_;
        paused = true;
    }

    modifier whenNotPaused() {
        if (paused) revert AlreadyPaused();
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyGateway() {
        if (msg.sender != gateway) revert NotGateway();
        _;
    }

    modifier onlyEmergencyAdmin() {
        if (msg.sender != emergencyAdmin) revert NotAdmin();
        _;
    }

    modifier onlyDisputeResolver() {
        if (msg.sender != disputeResolver) revert NotAdmin();
        _;
    }

    modifier nonReentrant() {
        if (unlocked != 1) revert Reentrancy();
        unlocked = 2;
        _;
        unlocked = 1;
    }

    function createLease(bytes32 nodeId, uint32 duration, bytes32 clientReference)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 leaseId)
    {
        if (duration == 0 || duration > MAX_DURATION) revert InvalidDuration();
        if (clientReference == bytes32(0) || usedClientReferences[clientReference]) {
            revert ReferenceUsed();
        }
        if (activeLeaseCount >= MAX_ACTIVE_LEASES) revert ActiveLeaseLimit();
        if (!nodeRegistry.isSchedulable(nodeId)) revert LeaseNotReady();

        NodeRegistryV1.Node memory node = nodeRegistry.getNode(nodeId);
        uint256 deposit = uint256(node.ratePerSecond) * duration;
        if (deposit == 0 || deposit > MAX_ESCROW) revert LimitExceeded();
        if (leaseCount == type(uint64).max) revert LimitExceeded();

        leaseId = ++leaseCount;
        leases[leaseId] = Lease({
            renter: msg.sender,
            nodeId: nodeId,
            clientReference: clientReference,
            ratePerSecond: node.ratePerSecond,
            // MAX_ESCROW is below the uint128 limit.
            // forge-lint: disable-next-line(unsafe-typecast)
            deposit: uint128(deposit),
            duration: duration,
            createdAt: uint64(block.timestamp),
            accessStartedAt: 0,
            accessEndedAt: 0,
            proposedUsageSeconds: 0,
            proposedAt: 0,
            nonce: 1,
            receiptHash: bytes32(0),
            status: LeaseStatus.Funded
        });
        usedClientReferences[clientReference] = true;
        activeLeaseCount += 1;
        usd.pull(msg.sender, deposit);
        // leaseCount cannot exceed uint64 because it is checked before increment.
        // forge-lint: disable-next-line(unsafe-typecast)
        nodeRegistry.setActiveLease(nodeId, uint64(leaseId));
        emit LeaseFunded(leaseId, nodeId, msg.sender, deposit, duration, clientReference);
    }

    function startAccess(uint256 leaseId) external onlyGateway whenNotPaused {
        Lease storage lease = _lease(leaseId);
        if (
            lease.status != LeaseStatus.Funded
                || block.timestamp > lease.createdAt + PROVISION_TIMEOUT
        ) {
            revert InvalidState();
        }
        lease.status = LeaseStatus.Active;
        lease.accessStartedAt = uint64(block.timestamp);
        emit LeaseAccessStarted(leaseId, lease.accessStartedAt);
    }

    function closeAccess(uint256 leaseId) external onlyGateway {
        Lease storage lease = _lease(leaseId);
        if (lease.status != LeaseStatus.Active || lease.accessEndedAt != 0) revert InvalidState();
        lease.accessEndedAt = uint64(block.timestamp);
        emit LeaseAccessClosed(leaseId, lease.accessEndedAt);
    }

    function cancelUnprovisioned(uint256 leaseId, bytes32 reasonHash) external nonReentrant {
        Lease storage lease = _lease(leaseId);
        if (lease.renter != msg.sender) revert NotRenter();
        if (lease.status != LeaseStatus.Funded) revert InvalidState();
        _refund(leaseId, lease, reasonHash);
    }

    function expireProvision(uint256 leaseId, bytes32 reasonHash) external nonReentrant {
        Lease storage lease = _lease(leaseId);
        if (
            lease.status != LeaseStatus.Funded
                || block.timestamp <= lease.createdAt + PROVISION_TIMEOUT
        ) {
            revert InvalidState();
        }
        _refund(leaseId, lease, reasonHash);
    }

    function forceClose(uint256 leaseId) external {
        Lease storage lease = _lease(leaseId);
        if (
            lease.renter != msg.sender || lease.status != LeaseStatus.Active
                || lease.accessEndedAt != 0
        ) {
            revert Unauthorized();
        }
        if (block.timestamp <= lease.accessStartedAt + lease.duration) revert SettlementTooEarly();
        lease.accessEndedAt = lease.accessStartedAt + lease.duration;
        emit LeaseAccessClosed(leaseId, lease.accessEndedAt);
    }

    function proposeSettlement(
        uint256 leaseId,
        uint64 usageSeconds,
        bytes32 receiptHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        Lease storage lease = _lease(leaseId);
        if (
            lease.status != LeaseStatus.Active || lease.accessEndedAt == 0
                || receiptHash == bytes32(0)
        ) {
            revert InvalidState();
        }
        if (block.timestamp > deadline) revert Expired();
        uint256 maxUsage = _maxUsage(lease);
        if (usageSeconds > maxUsage || uint256(usageSeconds) * lease.ratePerSecond > lease.deposit)
        {
            revert UsageExceeded();
        }
        bytes32 digest = _hashTypedData(
            keccak256(
                abi.encode(
                    SETTLEMENT_TYPEHASH, leaseId, usageSeconds, receiptHash, lease.nonce, deadline
                )
            )
        );
        if (_recover(digest, signature) != attestor) revert InvalidSignature();

        lease.status = LeaseStatus.SettlementProposed;
        lease.proposedUsageSeconds = usageSeconds;
        lease.proposedAt = uint64(block.timestamp);
        lease.receiptHash = receiptHash;
        emit SettlementProposed(leaseId, usageSeconds, receiptHash, deadline);
    }

    function dispute(uint256 leaseId) external {
        Lease storage lease = _lease(leaseId);
        if (lease.renter != msg.sender) revert NotRenter();
        if (
            lease.status != LeaseStatus.SettlementProposed
                || block.timestamp > lease.proposedAt + DISPUTE_WINDOW
        ) {
            revert InvalidState();
        }
        lease.status = LeaseStatus.Disputed;
        emit LeaseDisputed(leaseId, msg.sender);
    }

    function finalize(uint256 leaseId) external nonReentrant {
        Lease storage lease = _lease(leaseId);
        if (
            lease.status != LeaseStatus.SettlementProposed
                || block.timestamp < lease.proposedAt + DISPUTE_WINDOW
        ) {
            revert SettlementTooEarly();
        }
        _settle(leaseId, lease, lease.proposedUsageSeconds, lease.receiptHash);
    }

    function resolveDispute(uint256 leaseId, uint64 usageSeconds, bytes32 receiptHash)
        external
        onlyDisputeResolver
        nonReentrant
    {
        Lease storage lease = _lease(leaseId);
        if (lease.status != LeaseStatus.Disputed || receiptHash == bytes32(0)) {
            revert InvalidState();
        }
        uint256 maxUsage = _maxUsage(lease);
        if (usageSeconds > maxUsage || uint256(usageSeconds) * lease.ratePerSecond > lease.deposit)
        {
            revert UsageExceeded();
        }
        _settle(leaseId, lease, usageSeconds, receiptHash);
    }

    function pause() external onlyEmergencyAdmin {
        if (paused) revert AlreadyPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyAdmin {
        if (!paused) revert NotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }

    function setGateway(address gateway_) external onlyAdmin {
        if (gateway_ == address(0)) revert InvalidAddress();
        gateway = gateway_;
        emit GatewaySet(gateway_);
    }

    function setAttestor(address attestor_) external onlyAdmin {
        if (attestor_ == address(0)) revert InvalidAddress();
        attestor = attestor_;
        emit AttestorSet(attestor_);
    }

    function getLease(uint256 leaseId) external view returns (Lease memory) {
        return _lease(leaseId);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _settle(uint256 leaseId, Lease storage lease, uint64 usageSeconds, bytes32 receiptHash)
        private
    {
        uint256 charged = uint256(usageSeconds) * lease.ratePerSecond;
        uint256 fee = charged * PLATFORM_FEE_BPS / BPS_DENOMINATOR;
        uint256 providerPaid = charged - fee;
        uint256 refunded = lease.deposit - charged;
        NodeRegistryV1.Node memory node = nodeRegistry.getNode(lease.nodeId);

        lease.status = LeaseStatus.Finalized;
        lease.receiptHash = receiptHash;
        activeLeaseCount -= 1;
        nodeRegistry.setActiveLease(lease.nodeId, 0);
        if (providerPaid != 0) usd.push(node.payout, providerPaid);
        if (fee != 0) usd.push(treasury, fee);
        if (refunded != 0) usd.push(lease.renter, refunded);
        emit LeaseFinalized(leaseId, charged, fee, providerPaid, refunded, receiptHash);
    }

    function _refund(uint256 leaseId, Lease storage lease, bytes32 reasonHash) private {
        uint256 refunded = lease.deposit;
        lease.status = LeaseStatus.Refunded;
        activeLeaseCount -= 1;
        nodeRegistry.setActiveLease(lease.nodeId, 0);
        usd.push(lease.renter, refunded);
        emit LeaseRefunded(leaseId, refunded, reasonHash);
    }

    function _lease(uint256 leaseId) private view returns (Lease storage lease) {
        lease = leases[leaseId];
        if (lease.status == LeaseStatus.None) revert InvalidLease();
    }

    function _maxUsage(Lease storage lease) private view returns (uint256) {
        uint256 observed = lease.accessEndedAt - lease.accessStartedAt;
        return observed > lease.duration ? lease.duration : observed;
    }

    function _hashTypedData(bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _domainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("Prism Network"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata signature)
        private
        pure
        returns (address signer)
    {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if ((v != 27 && v != 28) || uint256(s) > SECP256K1N_DIV_2) return address(0);
        signer = ecrecover(digest, v, r, s);
    }
}
