// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "./interfaces/IERC20.sol";
import { TokenTransfers } from "./lib/TokenTransfers.sol";

contract NodeRegistryV1 {
    using TokenTransfers for IERC20;

    uint256 public constant MIN_BOND = 100_000_000;
    uint256 public constant DAY = 24 hours;
    uint256 private constant SECP256K1N_DIV_2 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    bytes32 public constant DEVICE_BINDING_TYPEHASH = keccak256(
        "DeviceBinding(bytes32 nodeId,bytes32 deviceHash,address operator,address payout,uint128 ratePerSecond,bytes32 metadataHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant NAME_HASH = keccak256("Prism Node Registry");
    bytes32 private constant VERSION_HASH = keccak256("1");

    enum NodeStatus {
        None,
        Active,
        Suspended,
        Retired
    }

    struct Node {
        address operator;
        address payout;
        bytes32 deviceHash;
        bytes32 metadataHash;
        uint128 ratePerSecond;
        uint128 bond;
        uint64 activeLeaseId;
        NodeStatus status;
    }

    error AlreadyRegistered();
    error InvalidAddress();
    error InvalidNode();
    error InvalidRate();
    error EnrollmentExpired();
    error InvalidEnrollmentSignature();
    error InsufficientBond(uint256 required, uint256 available);
    error LeaseActive();
    error NotEscrow();
    error NotOperator();
    error NotOwner();
    error Reentrancy();

    event NodeRegistered(
        bytes32 indexed nodeId,
        address indexed operator,
        address indexed payout,
        uint256 ratePerSecond
    );
    event NodeOfferUpdated(bytes32 indexed nodeId, uint256 ratePerSecond, bytes32 metadataHash);
    event NodeBonded(bytes32 indexed nodeId, uint256 amount, uint256 totalBond);
    event NodeWithdrawn(bytes32 indexed nodeId, uint256 amount, uint256 totalBond);
    event NodeStatusChanged(bytes32 indexed nodeId, NodeStatus status);
    event NodeSlashed(bytes32 indexed nodeId, uint256 amount, bytes32 evidenceHash);
    event EscrowSet(address indexed escrow);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TreasurySet(address indexed treasury);

    IERC20 public immutable usd;
    address public owner;
    address public escrow;
    address public treasury;
    uint256 private unlocked = 1;
    mapping(bytes32 nodeId => Node node) private nodes;
    mapping(address operator => uint256 nonce) public enrollmentNonces;

    constructor(IERC20 usd_, address treasury_) {
        if (address(usd_) == address(0) || treasury_ == address(0)) {
            revert InvalidAddress();
        }
        usd = usd_;
        owner = msg.sender;
        treasury = treasury_;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyEscrow() {
        if (msg.sender != escrow) revert NotEscrow();
        _;
    }

    modifier nonReentrant() {
        if (unlocked != 1) revert Reentrancy();
        unlocked = 2;
        _;
        unlocked = 1;
    }

    function setEscrow(address escrow_) external onlyOwner {
        if (escrow_ == address(0) || escrow != address(0)) revert InvalidAddress();
        escrow = escrow_;
        emit EscrowSet(escrow_);
    }

    function transferOwnership(address owner_) external onlyOwner {
        if (owner_ == address(0)) revert InvalidAddress();
        address previousOwner = owner;
        owner = owner_;
        emit OwnershipTransferred(previousOwner, owner_);
    }

    function setTreasury(address treasury_) external onlyOwner {
        if (treasury_ == address(0)) revert InvalidAddress();
        treasury = treasury_;
        emit TreasurySet(treasury_);
    }

    function register(
        bytes32 nodeId,
        bytes32 deviceHash,
        address payout,
        uint128 ratePerSecond,
        bytes32 metadataHash,
        uint256 deadline,
        bytes calldata operatorSignature
    ) external nonReentrant {
        if (nodes[nodeId].status != NodeStatus.None) {
            revert AlreadyRegistered();
        }
        if (nodeId == bytes32(0) || deviceHash != nodeId || payout == address(0)) {
            revert InvalidNode();
        }
        if (ratePerSecond == 0) revert InvalidRate();

        uint256 nonce = enrollmentNonces[msg.sender];
        if (deadline < block.timestamp) revert EnrollmentExpired();
        if (
            _recover(
                    enrollmentDigest(
                        nodeId,
                        deviceHash,
                        msg.sender,
                        payout,
                        ratePerSecond,
                        metadataHash,
                        nonce,
                        deadline
                    ),
                    operatorSignature
                ) != msg.sender
        ) {
            revert InvalidEnrollmentSignature();
        }
        enrollmentNonces[msg.sender] = nonce + 1;

        uint256 required = requiredBond(ratePerSecond);
        if (required > type(uint128).max) revert InvalidRate();
        nodes[nodeId] = Node({
            operator: msg.sender,
            payout: payout,
            deviceHash: deviceHash,
            metadataHash: metadataHash,
            ratePerSecond: ratePerSecond,
            // The required-bond bound check makes this conversion exact.
            // forge-lint: disable-next-line(unsafe-typecast)
            bond: uint128(required),
            activeLeaseId: 0,
            status: NodeStatus.Active
        });
        usd.pull(msg.sender, required);
        emit NodeRegistered(nodeId, msg.sender, payout, ratePerSecond);
    }

    function topUpBond(bytes32 nodeId, uint128 amount) external nonReentrant {
        Node storage node = _operatorNode(nodeId);
        if (amount == 0) revert InvalidNode();
        usd.pull(msg.sender, amount);
        node.bond += amount;
        emit NodeBonded(nodeId, amount, node.bond);
    }

    function updateOffer(bytes32 nodeId, uint128 ratePerSecond, bytes32 metadataHash) external {
        Node storage node = _operatorNode(nodeId);
        if (node.activeLeaseId != 0) revert LeaseActive();
        if (ratePerSecond == 0) revert InvalidRate();
        _requireBond(ratePerSecond, node.bond);
        node.ratePerSecond = ratePerSecond;
        node.metadataHash = metadataHash;
        emit NodeOfferUpdated(nodeId, ratePerSecond, metadataHash);
    }

    function withdrawBond(bytes32 nodeId, uint128 amount) external nonReentrant {
        Node storage node = _operatorNode(nodeId);
        if (node.activeLeaseId != 0) revert LeaseActive();
        if (amount == 0 || amount > node.bond) revert InvalidNode();
        uint256 remaining = node.bond - amount;
        if (node.status != NodeStatus.Retired) {
            _requireBond(node.ratePerSecond, remaining);
        }
        node.bond -= amount;
        usd.push(msg.sender, amount);
        emit NodeWithdrawn(nodeId, amount, remaining);
    }

    function retire(bytes32 nodeId) external {
        Node storage node = _operatorNode(nodeId);
        if (node.activeLeaseId != 0) revert LeaseActive();
        node.status = NodeStatus.Retired;
        emit NodeStatusChanged(nodeId, NodeStatus.Retired);
    }

    function setSuspended(bytes32 nodeId, bool suspended) external onlyOwner {
        Node storage node = _node(nodeId);
        if (node.status == NodeStatus.Retired) revert InvalidNode();
        node.status = suspended ? NodeStatus.Suspended : NodeStatus.Active;
        emit NodeStatusChanged(nodeId, node.status);
    }

    function slash(bytes32 nodeId, uint128 amount, bytes32 evidenceHash)
        external
        onlyOwner
        nonReentrant
    {
        Node storage node = _node(nodeId);
        if (amount == 0 || amount > node.bond || evidenceHash == bytes32(0)) revert InvalidNode();
        node.bond -= amount;
        if (node.bond < requiredBond(node.ratePerSecond)) {
            node.status = NodeStatus.Suspended;
            emit NodeStatusChanged(nodeId, NodeStatus.Suspended);
        }
        usd.push(treasury, amount);
        emit NodeSlashed(nodeId, amount, evidenceHash);
    }

    function setActiveLease(bytes32 nodeId, uint64 leaseId) external onlyEscrow {
        Node storage node = _node(nodeId);
        if (leaseId == 0) {
            node.activeLeaseId = 0;
            return;
        }
        if (node.status != NodeStatus.Active || node.activeLeaseId != 0) revert LeaseActive();
        _requireBond(node.ratePerSecond, node.bond);
        node.activeLeaseId = leaseId;
    }

    function getNode(bytes32 nodeId) external view returns (Node memory) {
        return _node(nodeId);
    }

    function isSchedulable(bytes32 nodeId) external view returns (bool) {
        Node storage node = nodes[nodeId];
        return node.status == NodeStatus.Active && node.activeLeaseId == 0
            && node.bond >= requiredBond(node.ratePerSecond);
    }

    function requiredBond(uint128 ratePerSecond) public pure returns (uint256) {
        uint256 dayRate = uint256(ratePerSecond) * DAY;
        return dayRate > MIN_BOND ? dayRate : MIN_BOND;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    function enrollmentDigest(
        bytes32 nodeId,
        bytes32 deviceHash,
        address operator,
        address payout,
        uint128 ratePerSecond,
        bytes32 metadataHash,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                DEVICE_BINDING_TYPEHASH,
                nodeId,
                deviceHash,
                operator,
                payout,
                ratePerSecond,
                metadataHash,
                nonce,
                deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _operatorNode(bytes32 nodeId) private view returns (Node storage node) {
        node = _node(nodeId);
        if (node.operator != msg.sender) revert NotOperator();
    }

    function _node(bytes32 nodeId) private view returns (Node storage node) {
        node = nodes[nodeId];
        if (node.status == NodeStatus.None) revert InvalidNode();
    }

    function _requireBond(uint128 ratePerSecond, uint256 bond) private pure {
        uint256 required = requiredBond(ratePerSecond);
        if (bond < required) revert InsufficientBond(required, bond);
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
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
        return ecrecover(digest, v, r, s);
    }
}
